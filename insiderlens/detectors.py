"""
InsiderLens - Detection Engine
Ensemble of detectors for insider threat detection from encrypted traffic metadata.
"""
import numpy as np
import pandas as pd
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime
import math
import warnings
warnings.filterwarnings('ignore')


@dataclass
class DetectorResult:
    """Standard output from any detector."""
    detector_name: str
    user_id: str
    score: float  # 0-1 normalized
    evidence_tags: List[str] = field(default_factory=list)
    details: Dict = field(default_factory=dict)
    kill_chain_stage: int = 0  # 0=unknown, 1=recon, 2=staging, 3=exfil, 4=cover-up
    timestamp: str = ""


class FlowClassifier:
    """
    Detector A: XGBoost-based flow-level exfiltration classifier.
    Trained on flow features to classify upload/exfil-like flows.
    """

    def __init__(self):
        self.model = None
        self.feature_cols = []
        self.is_trained = False

    def train(self, flows: pd.DataFrame):
        """Train the XGBoost flow classifier."""
        from xgboost import XGBClassifier
        from sklearn.model_selection import train_test_split

        # Create binary label: exfil-like flows
        flows = flows.copy()
        flows["is_exfil"] = self._create_exfil_labels(flows)

        self.feature_cols = [
            "bytes_out", "bytes_in", "upload_ratio", "duration_seconds",
            "packets_out", "packets_in", "bytes_per_sec_out",
            "bytes_per_pkt_out", "total_bytes", "is_after_hours",
            "is_weekend", "has_sni", "dns_query_length", "dns_query_entropy",
            "is_new_destination",
        ]

        # Ensure all columns exist
        for col in self.feature_cols:
            if col not in flows.columns:
                flows[col] = 0

        X = flows[self.feature_cols].fillna(0)
        y = flows["is_exfil"]

        X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

        self.model = XGBClassifier(
            n_estimators=100,
            max_depth=5,
            learning_rate=0.1,
            scale_pos_weight=max(1, (y == 0).sum() / max((y == 1).sum(), 1)),
            random_state=42,
            use_label_encoder=False,
            eval_metric="logloss",
        )
        self.model.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=False)
        self.is_trained = True

        return self

    def predict(self, flows: pd.DataFrame) -> List[DetectorResult]:
        """Score flows for exfiltration likelihood."""
        results = []
        if not self.is_trained:
            return results

        for col in self.feature_cols:
            if col not in flows.columns:
                flows[col] = 0

        X = flows[self.feature_cols].fillna(0)
        proba = self.model.predict_proba(X)[:, 1]

        for idx, (_, row) in enumerate(flows.iterrows()):
            if proba[idx] > 0.3:
                tags = []
                if row.get("upload_ratio", 0) > 2:
                    tags.append("high_upload_ratio")
                if row.get("is_after_hours", 0):
                    tags.append("after_hours")
                if row.get("is_new_destination", 0):
                    tags.append("new_destination")
                if row.get("bytes_out", 0) > 50000:
                    tags.append("large_upload")

                results.append(DetectorResult(
                    detector_name="flow_classifier",
                    user_id=row.get("user_id", ""),
                    score=float(proba[idx]),
                    evidence_tags=tags,
                    details={
                        "flow_id": row.get("flow_id", ""),
                        "bytes_out": int(row.get("bytes_out", 0)),
                        "dst_ip": row.get("dst_ip", ""),
                        "upload_ratio": round(float(row.get("upload_ratio", 0)), 3),
                    },
                    kill_chain_stage=3,
                    timestamp=str(row.get("timestamp", "")),
                ))
        return results

    def get_shap_values(self, flows: pd.DataFrame):
        """Get SHAP explanations for predictions."""
        if not self.is_trained:
            return None
        import shap
        for col in self.feature_cols:
            if col not in flows.columns:
                flows[col] = 0
        X = flows[self.feature_cols].fillna(0)
        explainer = shap.TreeExplainer(self.model)
        shap_values = explainer.shap_values(X)
        return shap_values, self.feature_cols

    @staticmethod
    def _create_exfil_labels(flows: pd.DataFrame) -> pd.Series:
        """Create synthetic exfil labels based on scenario tags and heuristics."""
        labels = pd.Series(0, index=flows.index)

        # Mark scenario-labeled suspicious flows
        suspicious_scenarios = [
            "gradual_outbound_increase",
            "unusual_destination_burst",
            "repeated_after_hours_activity",
        ]
        labels[flows["scenario_label"].isin(suspicious_scenarios)] = 1

        # Also flag extreme upload ratios + large bytes in normal traffic as potential exfil
        labels[(flows["upload_ratio"] > 5) & (flows["bytes_out"] > 100000)] = 1

        return labels


class UserAnomalyDetector:
    """
    Detector B: Per-user and peer-group anomaly detection using Isolation Forest.
    """

    def __init__(self):
        self.user_model = None
        self.peer_models = {}
        self.feature_cols = []
        self.is_trained = False

    def train(self, daily_features: pd.DataFrame):
        """Train anomaly detectors on daily user features."""
        from sklearn.ensemble import IsolationForest

        self.feature_cols = [
            "total_bytes_out", "total_flows", "unique_destinations",
            "after_hours_ratio", "mean_upload_ratio", "max_bytes_out",
            "new_destinations", "mean_bytes_per_sec",
        ]

        existing_cols = [c for c in self.feature_cols if c in daily_features.columns]
        self.feature_cols = existing_cols

        X = daily_features[self.feature_cols].fillna(0)

        # Global anomaly detector
        self.user_model = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42,
        )
        self.user_model.fit(X)

        # Per-department (peer group) models
        for dept in daily_features["department"].unique():
            dept_data = daily_features[daily_features["department"] == dept]
            if len(dept_data) >= 5:
                X_dept = dept_data[self.feature_cols].fillna(0)
                model = IsolationForest(
                    n_estimators=50,
                    contamination=0.15,
                    random_state=42,
                )
                model.fit(X_dept)
                self.peer_models[dept] = model

        self.is_trained = True
        return self

    def predict(self, daily_features: pd.DataFrame) -> List[DetectorResult]:
        """Detect anomalous user-days."""
        results = []
        if not self.is_trained:
            return results

        X = daily_features[self.feature_cols].fillna(0)

        # Global anomaly scores (convert from [-1, 1] to [0, 1])
        raw_scores = self.user_model.decision_function(X)
        scores = 1 - (raw_scores - raw_scores.min()) / (raw_scores.max() - raw_scores.min() + 1e-6)

        for idx, (_, row) in enumerate(daily_features.iterrows()):
            score = float(scores[idx])

            # Add peer-group score if available
            dept = row.get("department", "")
            if dept in self.peer_models:
                x_single = X.iloc[idx:idx+1]
                peer_raw = self.peer_models[dept].decision_function(x_single)[0]
                peer_score = max(0, -peer_raw)  # Higher = more anomalous
                score = 0.6 * score + 0.4 * min(1.0, peer_score)

            if score > 0.4:
                tags = []
                if row.get("total_bytes_out", 0) > daily_features["total_bytes_out"].quantile(0.9):
                    tags.append("high_volume_day")
                if row.get("after_hours_ratio", 0) > 0.3:
                    tags.append("high_after_hours")
                if row.get("new_destinations", 0) > daily_features["new_destinations"].quantile(0.9):
                    tags.append("many_new_destinations")
                if row.get("unique_destinations", 0) > daily_features["unique_destinations"].quantile(0.9):
                    tags.append("many_unique_destinations")

                results.append(DetectorResult(
                    detector_name="user_anomaly",
                    user_id=row.get("user_id", ""),
                    score=min(1.0, score),
                    evidence_tags=tags,
                    details={
                        "date": str(row.get("date", "")),
                        "total_bytes_out": int(row.get("total_bytes_out", 0)),
                        "total_flows": int(row.get("total_flows", 0)),
                        "unique_destinations": int(row.get("unique_destinations", 0)),
                        "department": dept,
                    },
                    kill_chain_stage=3,
                    timestamp=str(row.get("date", "")),
                ))
        return results


class DNSTunnelDetector:
    """
    Detector D1: DNS tunneling detection based on statistical features.
    """

    def predict(self, flows: pd.DataFrame) -> List[DetectorResult]:
        """Detect potential DNS tunneling in flows."""
        results = []
        dns_flows = flows[flows["dns_query"].notna() & (flows["dns_query"] != "")].copy()

        for _, row in dns_flows.iterrows():
            query = str(row.get("dns_query", ""))
            if not query or query == "nan":
                continue

            # DNS tunneling indicators
            score = 0.0
            tags = []

            # Long query names
            qlen = len(query)
            if qlen > 50:
                score += 0.3
                tags.append("long_dns_query")
            elif qlen > 30:
                score += 0.1

            # High entropy in subdomain
            labels = query.split(".")
            if len(labels) > 2:
                subdomain = ".".join(labels[:-2])
                entropy = self._entropy(subdomain)
                if entropy > 4.0:
                    score += 0.3
                    tags.append("high_entropy_subdomain")
                elif entropy > 3.0:
                    score += 0.1

            # Many labels
            if len(labels) > 5:
                score += 0.2
                tags.append("many_dns_labels")

            # Large bytes out via DNS (unusual)
            if row.get("dst_port", 0) == 53 and row.get("bytes_out", 0) > 5000:
                score += 0.2
                tags.append("large_dns_payload")

            if score > 0.3:
                results.append(DetectorResult(
                    detector_name="dns_tunnel",
                    user_id=row.get("user_id", ""),
                    score=min(1.0, score),
                    evidence_tags=tags,
                    details={
                        "flow_id": row.get("flow_id", ""),
                        "dns_query": query[:60],
                        "query_length": qlen,
                    },
                    kill_chain_stage=3,
                    timestamp=str(row.get("timestamp", "")),
                ))
        return results

    @staticmethod
    def _entropy(s: str) -> float:
        from collections import Counter
        if not s:
            return 0.0
        c = Counter(s)
        n = len(s)
        return -sum((v / n) * math.log2(v / n) for v in c.values())


class BeaconingDetector:
    """
    Detector D2: Beaconing detection via inter-arrival time regularity.
    """

    def predict(self, flows: pd.DataFrame) -> List[DetectorResult]:
        """Detect beaconing patterns per user-destination pair."""
        results = []
        flows = flows.copy()
        flows["timestamp"] = pd.to_datetime(flows["timestamp"])

        # Group by user-destination
        for (user_id, dst_ip), group in flows.groupby(["user_id", "dst_ip"]):
            if len(group) < 5:
                continue

            times = group["timestamp"].sort_values()
            intervals = times.diff().dt.total_seconds().dropna()

            if len(intervals) < 3:
                continue

            # Coefficient of variation (low = regular = beaconing)
            mean_iat = intervals.mean()
            std_iat = intervals.std()

            if mean_iat == 0:
                continue

            cv = std_iat / (mean_iat + 1e-6)

            score = 0.0
            tags = []

            # Very regular intervals
            if cv < 0.1:
                score = 0.9
                tags.append("very_regular_intervals")
            elif cv < 0.3:
                score = 0.6
                tags.append("regular_intervals")
            elif cv < 0.5:
                score = 0.3
                tags.append("somewhat_regular")

            # Consistent packet sizes
            size_cv = group["bytes_out"].std() / (group["bytes_out"].mean() + 1e-6)
            if size_cv < 0.2:
                score += 0.1
                tags.append("consistent_payload_size")

            if score > 0.3:
                results.append(DetectorResult(
                    detector_name="beaconing",
                    user_id=str(user_id),
                    score=min(1.0, score),
                    evidence_tags=tags,
                    details={
                        "dst_ip": str(dst_ip),
                        "interval_cv": round(cv, 4),
                        "mean_interval_sec": round(mean_iat, 1),
                        "connection_count": len(group),
                    },
                    kill_chain_stage=1,
                ))
        return results


class LowAndSlowDetector:
    """
    Detector E: CUSUM/EWMA-based low-and-slow exfiltration detection.
    Catches gradual, persistent data drips over long windows.
    """

    def __init__(self, k: float = 0.5, h: float = 4.0):
        self.k = k  # CUSUM allowance
        self.h = h  # CUSUM threshold

    def predict(self, daily_features: pd.DataFrame) -> List[DetectorResult]:
        """Detect low-and-slow patterns in daily user features."""
        results = []
        df = daily_features.sort_values(["user_id", "date"])

        for user_id, user_data in df.groupby("user_id"):
            if len(user_data) < 5:
                continue

            series = user_data["total_bytes_out"].values

            # CUSUM detection
            cusum_alerts = self._cusum(series, k=self.k, h=self.h)
            # EWMA detection
            ewma_alerts = self._ewma(series, span=5, threshold=2.0)

            for i, (cs_alert, ew_alert) in enumerate(zip(cusum_alerts, ewma_alerts)):
                if cs_alert or ew_alert:
                    row = user_data.iloc[i]
                    score = 0.0
                    tags = []

                    if cs_alert:
                        score += 0.5
                        tags.append("cusum_shift_detected")
                    if ew_alert:
                        score += 0.4
                        tags.append("ewma_trend_detected")

                    # Check cumulative windows
                    if "cum_bytes_out_7d" in row.index:
                        cum_7d = row.get("cum_bytes_out_7d", 0)
                        if cum_7d > daily_features["total_bytes_out"].quantile(0.95) * 7:
                            score += 0.2
                            tags.append("high_7d_cumulative")

                    results.append(DetectorResult(
                        detector_name="low_and_slow",
                        user_id=str(user_id),
                        score=min(1.0, score),
                        evidence_tags=tags,
                        details={
                            "date": str(row.get("date", "")),
                            "bytes_out": int(row.get("total_bytes_out", 0)),
                            "cusum_triggered": cs_alert,
                            "ewma_triggered": ew_alert,
                        },
                        kill_chain_stage=3,
                        timestamp=str(row.get("date", "")),
                    ))
        return results

    @staticmethod
    def _cusum(series, k=0.5, h=4.0):
        """Cumulative Sum control chart."""
        target = np.mean(series[:max(3, len(series) // 3)])
        sigma = np.std(series[:max(3, len(series) // 3)]) + 1e-6
        s_pos = 0.0
        alerts = []
        for x in series:
            z = (x - target) / sigma
            s_pos = max(0.0, s_pos + z - k)
            alerts.append(s_pos > h)
        return alerts

    @staticmethod
    def _ewma(series, span=5, threshold=2.0):
        """Exponentially Weighted Moving Average detector."""
        ewma = pd.Series(series).ewm(span=span).mean()
        ewma_std = pd.Series(series).ewm(span=span).std()
        residuals = (pd.Series(series) - ewma) / (ewma_std + 1e-6)
        return (residuals > threshold).tolist()


class VolumeAnomalyDetector:
    """
    Detects sudden volume spikes and upload asymmetry anomalies.
    """

    def predict(self, daily_features: pd.DataFrame) -> List[DetectorResult]:
        """Detect volume anomalies in daily features."""
        results = []
        df = daily_features.copy()

        for _, row in df.iterrows():
            score = 0.0
            tags = []

            # Z-score vs self history
            z_self = row.get("total_bytes_out_z_self", 0)
            if not np.isnan(z_self):
                if abs(z_self) > 3:
                    score += 0.5
                    tags.append("extreme_volume_deviation")
                elif abs(z_self) > 2:
                    score += 0.3
                    tags.append("high_volume_deviation")

            # Z-score vs peer group
            z_peer = row.get("total_bytes_out_z_peer", 0)
            if not np.isnan(z_peer):
                if abs(z_peer) > 3:
                    score += 0.3
                    tags.append("extreme_peer_deviation")
                elif abs(z_peer) > 2:
                    score += 0.15
                    tags.append("high_peer_deviation")

            # After hours ratio anomaly
            z_after = row.get("after_hours_ratio_z_self", 0)
            if not np.isnan(z_after) and z_after > 2:
                score += 0.2
                tags.append("unusual_after_hours")

            if score > 0.3:
                results.append(DetectorResult(
                    detector_name="volume_anomaly",
                    user_id=row.get("user_id", ""),
                    score=min(1.0, score),
                    evidence_tags=tags,
                    details={
                        "date": str(row.get("date", "")),
                        "total_bytes_out": int(row.get("total_bytes_out", 0)),
                        "z_self": round(float(z_self) if not np.isnan(z_self) else 0, 2),
                        "z_peer": round(float(z_peer) if not np.isnan(z_peer) else 0, 2),
                    },
                    kill_chain_stage=3,
                    timestamp=str(row.get("date", "")),
                ))
        return results


class DetectionEngine:
    """
    Ensemble detection engine that combines all detectors.
    """

    def __init__(self):
        self.flow_classifier = FlowClassifier()
        self.user_anomaly = UserAnomalyDetector()
        self.dns_tunnel = DNSTunnelDetector()
        self.beaconing = BeaconingDetector()
        self.low_and_slow = LowAndSlowDetector()
        self.volume_anomaly = VolumeAnomalyDetector()
        self.all_results: List[DetectorResult] = []

    def train(self, flows: pd.DataFrame, daily_features: pd.DataFrame):
        """Train all trainable detectors."""
        print("  Training Flow Classifier (XGBoost)...")
        self.flow_classifier.train(flows)
        print("  Training User Anomaly Detector (Isolation Forest)...")
        self.user_anomaly.train(daily_features)
        print("  Detection Engine training complete.")

    def run_all(self, flows: pd.DataFrame, daily_features: pd.DataFrame) -> List[DetectorResult]:
        """Run all detectors and return combined results."""
        self.all_results = []

        print("  Running Flow Classifier...")
        self.all_results.extend(self.flow_classifier.predict(flows))

        print("  Running User Anomaly Detector...")
        self.all_results.extend(self.user_anomaly.predict(daily_features))

        print("  Running DNS Tunnel Detector...")
        self.all_results.extend(self.dns_tunnel.predict(flows))

        print("  Running Beaconing Detector...")
        self.all_results.extend(self.beaconing.predict(flows))

        print("  Running Low-and-Slow Detector...")
        self.all_results.extend(self.low_and_slow.predict(daily_features))

        print("  Running Volume Anomaly Detector...")
        self.all_results.extend(self.volume_anomaly.predict(daily_features))

        print(f"  Total alerts generated: {len(self.all_results)}")
        return self.all_results
