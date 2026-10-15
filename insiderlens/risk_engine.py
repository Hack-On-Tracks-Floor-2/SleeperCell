"""
InsiderLens - Risk Engine & Kill-Chain Correlation
Per-user risk scoring with exponential decay and kill-chain stage mapping.
"""
import math
import pandas as pd
import numpy as np
from typing import List, Dict, Optional
from datetime import datetime
from dataclasses import dataclass, field

from insiderlens.detectors import DetectorResult
from insiderlens.config import (
    RISK_THRESHOLDS, RISK_HALF_LIFE_HOURS,
    CONTEXT_MULTIPLIERS, DETECTOR_WEIGHTS, KILL_CHAIN_STAGES,
)


@dataclass
class Alert:
    """A single alert from the detection engine."""
    alert_id: str
    timestamp: str
    user_id: str
    detector: str
    score: float
    evidence_tags: List[str]
    shap_top_features: Dict = field(default_factory=dict)
    kill_chain_stage: int = 0
    case_id: str = ""
    status: str = "open"
    analyst_label: str = ""  # true_positive, false_positive, pending


@dataclass
class Case:
    """A correlated case linking multiple alerts for one user."""
    case_id: str
    user_id: str
    first_seen: str
    last_seen: str
    risk_score: float
    severity: str
    stages: List[int] = field(default_factory=list)
    alerts: List[Alert] = field(default_factory=list)
    narrative: str = ""
    status: str = "open"


class RiskEngine:
    """
    Manages per-user risk scores with exponential time decay,
    context multipliers, and severity classification.
    """

    def __init__(self):
        self.user_risks: Dict[str, float] = {}
        self.user_last_update: Dict[str, str] = {}
        self.alerts: List[Alert] = []
        self.cases: Dict[str, Case] = {}
        self._alert_counter = 0
        self._case_counter = 0

    def process_detector_results(
        self,
        results: List[DetectorResult],
        user_context: pd.DataFrame
    ) -> List[Alert]:
        """
        Process raw detector outputs into alerts and update risk scores.
        """
        new_alerts = []

        for result in results:
            user_id = result.user_id
            if not user_id:
                continue

            # Get context multiplier
            ctx_mult = self._get_context_multiplier(user_id, user_context)

            # Get detector weight
            weight = DETECTOR_WEIGHTS.get(result.detector_name, 10.0)

            # Update risk score with decay
            self._update_risk(user_id, result.score * weight * ctx_mult, result.timestamp)

            # Create alert
            self._alert_counter += 1
            alert = Alert(
                alert_id=f"ALT-{self._alert_counter:05d}",
                timestamp=result.timestamp,
                user_id=user_id,
                detector=result.detector_name,
                score=result.score,
                evidence_tags=result.evidence_tags,
                shap_top_features=result.details,
                kill_chain_stage=result.kill_chain_stage,
            )
            new_alerts.append(alert)
            self.alerts.append(alert)

        # Correlate into cases
        self._correlate_cases(new_alerts)

        return new_alerts

    def _update_risk(self, user_id: str, gain: float, timestamp: str):
        """Update risk score with exponential decay."""
        lam = math.log(2) / RISK_HALF_LIFE_HOURS
        prev_risk = self.user_risks.get(user_id, 0.0)

        # Calculate time delta
        dt_hours = 24.0  # Default to 1 day if no previous timestamp
        if user_id in self.user_last_update and timestamp:
            try:
                prev_time = pd.to_datetime(self.user_last_update[user_id])
                curr_time = pd.to_datetime(timestamp)
                dt_hours = max(0, (curr_time - prev_time).total_seconds() / 3600)
            except Exception:
                pass

        # Apply decay and add new signal
        decayed = prev_risk * math.exp(-lam * dt_hours)
        new_risk = min(100.0, decayed + gain)

        self.user_risks[user_id] = new_risk
        if timestamp:
            self.user_last_update[user_id] = timestamp

    def _get_context_multiplier(self, user_id: str, user_context: pd.DataFrame) -> float:
        """Get context-based risk multiplier for a user."""
        mult = 1.0
        user_row = user_context[user_context["user_id"] == user_id]
        if user_row.empty:
            return mult

        user_row = user_row.iloc[0]
        hr_status = str(user_row.get("hr_status", "Active")).lower()
        role = str(user_row.get("role", "")).lower()

        if hr_status in ["notice", "resigned", "departing"]:
            mult *= CONTEXT_MULTIPLIERS["departing_employee"]
        elif hr_status == "on leave":
            mult *= CONTEXT_MULTIPLIERS["on_leave"]

        if "contractor" in role:
            mult *= CONTEXT_MULTIPLIERS["contractor"]

        if any(p in role for p in ["admin", "manager", "lead", "director"]):
            mult *= CONTEXT_MULTIPLIERS["privileged_role"]

        return mult

    def _correlate_cases(self, new_alerts: List[Alert]):
        """Group alerts into cases by user and kill-chain stages."""
        # Group by user
        user_alerts: Dict[str, List[Alert]] = {}
        for alert in new_alerts:
            user_alerts.setdefault(alert.user_id, []).append(alert)

        for user_id, alerts in user_alerts.items():
            # Find or create case for this user
            existing_case = None
            for case in self.cases.values():
                if case.user_id == user_id and case.status == "open":
                    existing_case = case
                    break

            stages = list(set(a.kill_chain_stage for a in alerts if a.kill_chain_stage > 0))

            if existing_case:
                existing_case.alerts.extend(alerts)
                existing_case.stages = list(set(existing_case.stages + stages))
                existing_case.last_seen = max(a.timestamp for a in alerts if a.timestamp) or existing_case.last_seen
                existing_case.risk_score = self.user_risks.get(user_id, 0)
                existing_case.severity = self._severity(existing_case.risk_score)
                for alert in alerts:
                    alert.case_id = existing_case.case_id
            else:
                self._case_counter += 1
                case_id = f"CASE-{self._case_counter:04d}"
                timestamps = [a.timestamp for a in alerts if a.timestamp]
                case = Case(
                    case_id=case_id,
                    user_id=user_id,
                    first_seen=min(timestamps) if timestamps else "",
                    last_seen=max(timestamps) if timestamps else "",
                    risk_score=self.user_risks.get(user_id, 0),
                    severity=self._severity(self.user_risks.get(user_id, 0)),
                    stages=stages,
                    alerts=alerts,
                )
                self.cases[case_id] = case
                for alert in alerts:
                    alert.case_id = case_id

    @staticmethod
    def _severity(risk_score: float) -> str:
        """Map risk score to severity level."""
        if risk_score >= RISK_THRESHOLDS["critical"]:
            return "critical"
        elif risk_score >= RISK_THRESHOLDS["high"]:
            return "high"
        elif risk_score >= RISK_THRESHOLDS["medium"]:
            return "medium"
        elif risk_score >= RISK_THRESHOLDS["low"]:
            return "low"
        return "info"

    def get_risk_summary(self) -> pd.DataFrame:
        """Get a summary of all user risk scores."""
        data = []
        for user_id, risk in self.user_risks.items():
            data.append({
                "user_id": user_id,
                "risk_score": round(risk, 2),
                "severity": self._severity(risk),
                "alert_count": sum(1 for a in self.alerts if a.user_id == user_id),
                "case_count": sum(1 for c in self.cases.values() if c.user_id == user_id),
            })
        return pd.DataFrame(data).sort_values("risk_score", ascending=False)

    def get_cases_summary(self) -> pd.DataFrame:
        """Get summary of all cases."""
        data = []
        for case in self.cases.values():
            data.append({
                "case_id": case.case_id,
                "user_id": case.user_id,
                "risk_score": round(case.risk_score, 2),
                "severity": case.severity,
                "stages": case.stages,
                "alert_count": len(case.alerts),
                "first_seen": case.first_seen,
                "last_seen": case.last_seen,
                "status": case.status,
            })
        return pd.DataFrame(data).sort_values("risk_score", ascending=False)

    def get_user_timeline(self, user_id: str) -> List[Dict]:
        """Get chronological alert timeline for a user."""
        user_alerts = [a for a in self.alerts if a.user_id == user_id]
        user_alerts.sort(key=lambda a: a.timestamp if a.timestamp else "")
        return [
            {
                "alert_id": a.alert_id,
                "timestamp": a.timestamp,
                "detector": a.detector,
                "score": round(a.score, 3),
                "evidence": a.evidence_tags,
                "kill_chain_stage": KILL_CHAIN_STAGES.get(a.kill_chain_stage, "Unknown"),
            }
            for a in user_alerts
        ]
