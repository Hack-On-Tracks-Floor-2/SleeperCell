"""
InsiderLens - FastAPI Backend
REST API for the InsiderLens platform.
"""
import json
import pandas as pd
from pathlib import Path
from typing import Optional, List
from datetime import datetime
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(
    title="InsiderLens API",
    description="API for Insider Threat Detection Platform - Detecting data leaks in encrypted traffic",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Data paths
RESULTS_DIR = Path(__file__).parent / "results"
REPORTS_DIR = Path(__file__).parent / "reports"


# ── Pydantic Models ───────────────────────────────────────────────────

class RiskSummary(BaseModel):
    user_id: str
    risk_score: float
    severity: str
    alert_count: int
    case_count: int


class AlertResponse(BaseModel):
    alert_id: str
    timestamp: str
    user_id: str
    detector: str
    score: float
    evidence_tags: str
    kill_chain_stage: int
    case_id: str


class CopilotRequest(BaseModel):
    question: str


class CopilotResponse(BaseModel):
    answer: str
    context_used: List[str]


class RevealRequest(BaseModel):
    pseudo_id: str
    justification: str
    requester: str


class RevealResponse(BaseModel):
    status: str
    message: str


# ── Helper ─────────────────────────────────────────────────────────────

def load_csv(name: str) -> pd.DataFrame:
    path = RESULTS_DIR / name
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Data not found: {name}. Run the pipeline first.")
    return pd.read_csv(path)


# ── Audit log ──────────────────────────────────────────────────────────

audit_log = []

def log_audit(actor: str, action: str, target: str, result: str):
    audit_log.append({
        "ts": datetime.now().isoformat(),
        "actor": actor,
        "action": action,
        "target": target,
        "result": result,
    })


# ── Routes ─────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "name": "InsiderLens API",
        "version": "1.0.0",
        "status": "running",
        "description": "Detecting insider data leaks in encrypted traffic — without decrypting it",
    }


@app.get("/api/risk-summary", response_model=List[RiskSummary])
def get_risk_summary():
    """Get risk scores for all users, sorted by risk."""
    log_audit("API", "Query", "risk_summary", "Success")
    df = load_csv("risk_summary.csv")
    return df.to_dict(orient="records")


@app.get("/api/alerts")
def get_alerts(
    detector: Optional[str] = None,
    user_id: Optional[str] = None,
    min_score: float = 0.0,
    limit: int = Query(default=100, le=500),
):
    """Get alerts with optional filters."""
    log_audit("API", "Query", f"alerts (detector={detector}, user={user_id})", "Success")
    df = load_csv("alerts.csv")

    if detector:
        df = df[df["detector"] == detector]
    if user_id:
        df = df[df["user_id"] == user_id]
    df = df[df["score"] >= min_score]

    return df.sort_values("score", ascending=False).head(limit).to_dict(orient="records")


@app.get("/api/cases")
def get_cases():
    """Get all investigation cases."""
    log_audit("API", "Query", "cases", "Success")
    df = load_csv("cases_summary.csv")
    return df.to_dict(orient="records")


@app.get("/api/user/{user_id}")
def get_user_details(user_id: str):
    """Get detailed analysis for a specific user."""
    log_audit("API", "Query", f"user/{user_id}", "Success")

    risk = load_csv("risk_summary.csv")
    user_risk = risk[risk["user_id"] == user_id]
    if user_risk.empty:
        raise HTTPException(status_code=404, detail=f"User {user_id} not found")

    daily = load_csv("user_daily_features.csv")
    user_daily = daily[daily["user_id"] == user_id].to_dict(orient="records")

    alerts = load_csv("alerts.csv")
    user_alerts = alerts[alerts["user_id"] == user_id].to_dict(orient="records")

    # Load timeline
    timelines = {}
    tl_path = RESULTS_DIR / "timelines.json"
    if tl_path.exists():
        with open(tl_path, encoding="utf-8") as f:
            timelines = json.load(f)

    return {
        "risk": user_risk.iloc[0].to_dict(),
        "daily_features": user_daily,
        "alerts": user_alerts,
        "timeline": timelines.get(user_id, []),
    }


@app.get("/api/user/{user_id}/timeline")
def get_user_timeline(user_id: str):
    """Get chronological alert timeline for a user."""
    log_audit("API", "Query", f"timeline/{user_id}", "Success")
    tl_path = RESULTS_DIR / "timelines.json"
    if not tl_path.exists():
        return []
    with open(tl_path, encoding="utf-8") as f:
        timelines = json.load(f)
    return timelines.get(user_id, [])


@app.get("/api/explanations/{case_id}")
def get_explanation(case_id: str):
    """Get AI-generated explanation for a case."""
    log_audit("API", "Query", f"explanation/{case_id}", "Success")
    exp_path = RESULTS_DIR / "explanations.json"
    if not exp_path.exists():
        raise HTTPException(status_code=404, detail="Explanations not generated yet")
    with open(exp_path, encoding="utf-8") as f:
        explanations = json.load(f)
    if case_id not in explanations:
        raise HTTPException(status_code=404, detail=f"No explanation for {case_id}")
    return explanations[case_id]


@app.get("/api/report/{case_id}")
def get_report(case_id: str):
    """Get incident report for a case."""
    log_audit("API", "Query", f"report/{case_id}", "Success")
    report_file = REPORTS_DIR / f"report_{case_id.replace('-', '_')}.md"
    if not report_file.exists():
        raise HTTPException(status_code=404, detail=f"Report not found for {case_id}")
    return {"case_id": case_id, "report": report_file.read_text(encoding="utf-8")}


@app.post("/api/copilot")
def copilot_query(request: CopilotRequest):
    """AI copilot for natural-language threat hunting."""
    log_audit("API", "Copilot Query", request.question, "Processing")

    from insiderlens.genai_layer import GenAILayer
    genai = GenAILayer()

    risk = load_csv("risk_summary.csv")
    cases = load_csv("cases_summary.csv")

    context = {
        "risk_summary": risk.to_dict(orient="records"),
        "cases": cases.to_dict(orient="records"),
        "total_alerts": len(load_csv("alerts.csv")),
    }

    response = genai.generate_copilot_response(request.question, context)
    log_audit("API", "Copilot Query", request.question, "Success")

    return CopilotResponse(answer=response, context_used=["risk_summary", "cases"])


@app.post("/api/reveal")
def request_reveal(request: RevealRequest):
    """Request de-anonymization of a pseudonymous user ID."""
    log_audit(request.requester, "Reveal Request", request.pseudo_id, "Processing")

    risk = load_csv("risk_summary.csv")
    user_risk = risk[risk["user_id"] == request.pseudo_id]

    if user_risk.empty:
        raise HTTPException(status_code=404, detail="User not found")

    severity = user_risk.iloc[0]["severity"]

    if severity not in ["high", "critical"]:
        log_audit(request.requester, "Reveal Request", request.pseudo_id, "Denied - Insufficient risk")
        return RevealResponse(
            status="denied",
            message=f"Risk level ({severity}) is below the HIGH threshold required for identity reveal."
        )

    if not request.justification:
        return RevealResponse(status="denied", message="Justification is required.")

    log_audit(request.requester, "Reveal Request", request.pseudo_id, "Pending Approval")
    return RevealResponse(
        status="pending",
        message=f"Reveal request submitted for {request.pseudo_id}. Pending Lead approval."
    )


@app.get("/api/audit-log")
def get_audit_log():
    """Get the audit trail."""
    return audit_log


@app.get("/api/stats")
def get_stats():
    """Get system statistics."""
    risk = load_csv("risk_summary.csv")
    alerts = load_csv("alerts.csv")
    cases = load_csv("cases_summary.csv")

    return {
        "total_users": len(risk),
        "total_alerts": len(alerts),
        "total_cases": len(cases),
        "critical_users": len(risk[risk["severity"] == "critical"]),
        "high_users": len(risk[risk["severity"] == "high"]),
        "avg_risk_score": round(risk["risk_score"].mean(), 2),
        "max_risk_score": round(risk["risk_score"].max(), 2),
        "detectors_active": alerts["detector"].nunique(),
        "privacy_mode": "active",
        "last_pipeline_run": datetime.now().isoformat(),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
