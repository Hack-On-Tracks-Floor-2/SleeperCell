"""
InsiderLens - Data Pipeline Module
Handles loading, enrichment, identity mapping, and pseudonymization of flow data.
"""
import pandas as pd
import numpy as np
import hashlib
import json
from pathlib import Path
from datetime import datetime


class DataPipeline:
    """Complete data ingestion, enrichment, and identity mapping pipeline."""

    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)
        self._pseudonym_map = {}
        self._reverse_map = {}

    def load_all_data(self) -> dict:
        """Load all CSV data files into a dictionary of DataFrames."""
        data = {}
        data["flows"] = pd.read_csv(self.data_dir / "flows.csv")
        data["users"] = pd.read_csv(self.data_dir / "users.csv")
        data["roles"] = pd.read_csv(self.data_dir / "roles.csv")
        data["user_ip_map"] = pd.read_csv(self.data_dir / "user_ip_map.csv")
        data["devices"] = pd.read_csv(self.data_dir / "devices.csv")
        data["daily_features"] = pd.read_csv(self.data_dir / "daily_features.csv")
        data["scenarios"] = pd.read_csv(self.data_dir / "scenario_catalog.csv")

        with open(self.data_dir / "dataset_metadata.json", encoding="utf-8") as f:
            data["metadata"] = json.load(f)

        return data

    def enrich_flows(self, flows: pd.DataFrame) -> pd.DataFrame:
        """Add derived features to raw flow data."""
        df = flows.copy()

        # Parse timestamp
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df["date"] = df["timestamp"].dt.date.astype(str)
        df["hour"] = df["timestamp"].dt.hour
        df["day_of_week"] = df["timestamp"].dt.dayofweek
        df["is_weekend"] = (df["day_of_week"] >= 5).astype(int)
        df["is_after_hours"] = ((df["hour"] >= 20) | (df["hour"] < 7)).astype(int)

        # Upload ratio (key exfiltration indicator)
        df["upload_ratio"] = df["bytes_out"] / (df["bytes_in"] + 1)

        # Bytes per second
        df["bytes_per_sec_out"] = df["bytes_out"] / (df["duration_seconds"] + 1e-3)
        df["bytes_per_sec_in"] = df["bytes_in"] / (df["duration_seconds"] + 1e-3)

        # Packets per second
        df["pkts_per_sec_out"] = df["packets_out"] / (df["duration_seconds"] + 1e-3)
        df["pkts_per_sec_in"] = df["packets_in"] / (df["duration_seconds"] + 1e-3)

        # Bytes per packet
        df["bytes_per_pkt_out"] = df["bytes_out"] / (df["packets_out"] + 1)
        df["bytes_per_pkt_in"] = df["bytes_in"] / (df["packets_in"] + 1)

        # Total volume
        df["total_bytes"] = df["bytes_out"] + df["bytes_in"]
        df["total_packets"] = df["packets_out"] + df["packets_in"]

        # Domain-based features
        df["has_sni"] = df["tls_sni"].notna().astype(int)
        df["has_dns_query"] = df["dns_query"].notna().astype(int)

        # Domain categorization
        df["dst_category"] = df.apply(self._categorize_destination, axis=1)

        # Destination "newness" - first seen per user
        df = df.sort_values("timestamp")
        df["dst_first_seen"] = df.groupby(["user_id", "dst_ip"])["timestamp"].transform("min")
        df["is_new_destination"] = (df["timestamp"] == df["dst_first_seen"]).astype(int)

        # DNS query entropy (for DNS tunneling detection)
        df["dns_query_length"] = df["dns_query"].fillna("").str.len()
        df["dns_query_entropy"] = df["dns_query"].fillna("").apply(self._string_entropy)
        df["dns_label_count"] = df["dns_query"].fillna("").apply(lambda x: len(x.split(".")) if x else 0)

        return df

    def build_user_features(self, flows: pd.DataFrame, users: pd.DataFrame) -> pd.DataFrame:
        """Build per-user daily aggregate features for anomaly detection."""
        df = flows.copy()

        # Group by user and date
        daily = df.groupby(["user_id", "date"]).agg(
            total_flows=("flow_id", "count"),
            total_bytes_out=("bytes_out", "sum"),
            total_bytes_in=("bytes_in", "sum"),
            mean_bytes_out=("bytes_out", "mean"),
            max_bytes_out=("bytes_out", "max"),
            std_bytes_out=("bytes_out", "std"),
            mean_upload_ratio=("upload_ratio", "mean"),
            max_upload_ratio=("upload_ratio", "max"),
            unique_destinations=("dst_ip", "nunique"),
            unique_domains=("tls_sni", "nunique"),
            new_destinations=("is_new_destination", "sum"),
            after_hours_flows=("is_after_hours", "sum"),
            after_hours_ratio=("is_after_hours", "mean"),
            weekend_flows=("is_weekend", "sum"),
            tls_flows=("tls_used", "sum"),
            mean_duration=("duration_seconds", "mean"),
            total_packets_out=("packets_out", "sum"),
            total_packets_in=("packets_in", "sum"),
            mean_bytes_per_sec=("bytes_per_sec_out", "mean"),
            max_bytes_per_sec=("bytes_per_sec_out", "max"),
            cloud_storage_flows=("dst_category", lambda x: (x == "cloud_storage").sum()),
        ).reset_index()

        daily["std_bytes_out"] = daily["std_bytes_out"].fillna(0)

        # Merge user context
        daily = daily.merge(users[["user_id", "role", "department", "hr_status"]], on="user_id", how="left")

        # Upload ratio per day
        daily["daily_upload_ratio"] = daily["total_bytes_out"] / (daily["total_bytes_in"] + 1)

        # Bytes out in MB
        daily["total_bytes_out_mb"] = daily["total_bytes_out"] / (1024 * 1024)

        return daily

    def add_baseline_features(self, daily_features: pd.DataFrame) -> pd.DataFrame:
        """Add rolling baseline Z-scores and peer comparison features."""
        df = daily_features.copy()
        df = df.sort_values(["user_id", "date"])

        # Per-user Z-scores (compare to own history)
        for col in ["total_bytes_out", "total_flows", "unique_destinations",
                     "after_hours_ratio", "new_destinations"]:
            g = df.groupby("user_id")[col]
            rolling_mean = g.transform(lambda s: s.rolling(7, min_periods=2).mean().shift(1))
            rolling_std = g.transform(lambda s: s.rolling(7, min_periods=2).std().shift(1))
            df[f"{col}_z_self"] = (df[col] - rolling_mean) / (rolling_std + 1e-6)

        # Peer group comparison (same department)
        for col in ["total_bytes_out", "total_flows", "unique_destinations"]:
            peer_mean = df.groupby(["department", "date"])[col].transform("mean")
            peer_std = df.groupby(["department", "date"])[col].transform("std")
            df[f"{col}_z_peer"] = (df[col] - peer_mean) / (peer_std + 1e-6)
            df[f"{col}_pct_peer"] = df.groupby(["department", "date"])[col].transform(
                lambda x: x.rank(pct=True)
            )

        # Cumulative bytes over windows
        for window in [7, 14]:
            df[f"cum_bytes_out_{window}d"] = df.groupby("user_id")["total_bytes_out"].transform(
                lambda s: s.rolling(window, min_periods=1).sum()
            )

        return df

    def pseudonymize(self, user_id: str) -> str:
        """Create a pseudonymous ID for a user."""
        if user_id not in self._pseudonym_map:
            h = hashlib.sha256(f"insiderlens_salt_{user_id}".encode()).hexdigest()[:8]
            pseudo = f"U-{h.upper()}"
            self._pseudonym_map[user_id] = pseudo
            self._reverse_map[pseudo] = user_id
        return self._pseudonym_map[user_id]

    def reveal_identity(self, pseudo_id: str) -> str:
        """De-anonymize a pseudonymous ID (requires authorization in production)."""
        return self._reverse_map.get(pseudo_id, "UNKNOWN")

    @staticmethod
    def _categorize_destination(row) -> str:
        """Categorize destination based on SNI/domain."""
        sni = str(row.get("tls_sni", "")).lower()
        dns = str(row.get("dns_query", "")).lower()
        domain = sni if sni and sni != "nan" else dns

        if not domain or domain == "nan":
            return "unknown"

        cloud_keywords = ["storage", "drive", "dropbox", "mega", "wetransfer", "onedrive", "box"]
        mail_keywords = ["mail", "gmail", "outlook", "proton"]
        internal_keywords = ["example.test", "internal", "corp"]

        if any(k in domain for k in cloud_keywords):
            return "cloud_storage"
        elif any(k in domain for k in mail_keywords):
            return "webmail"
        elif any(k in domain for k in internal_keywords):
            return "internal"
        else:
            return "external"

    @staticmethod
    def _string_entropy(s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        from collections import Counter
        import math
        c = Counter(s)
        n = len(s)
        return -sum((v / n) * math.log2(v / n) for v in c.values()) if n > 0 else 0.0
