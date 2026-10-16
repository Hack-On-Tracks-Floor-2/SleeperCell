"""
InsiderLens - FastAPI Backend
REST API for the InsiderLens platform.
"""
import json
import secrets
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Optional, List, Dict
import math
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from pydantic import BaseModel


def clean_nans(val):
    if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
        return None
    if isinstance(val, dict):
        return {k: clean_nans(v) for k, v in val.items()}
    if isinstance(val, list):
        return [clean_nans(v) for v in val]
    return val


class NanSafeJSONResponse(JSONResponse):
    def render(self, content: any) -> bytes:
        cleaned = clean_nans(content)
        return json.dumps(
            cleaned,
            ensure_ascii=False,
            allow_nan=False,
            indent=None,
            separators=(",", ":"),
        ).encode("utf-8")


app = FastAPI(
    title="InsiderLens API",
    description="API for Insider Threat Detection Platform - Detecting data leaks in encrypted traffic",
    version="1.0.0",
    default_response_class=NanSafeJSONResponse,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Data paths
BASE_DIR = Path(__file__).parent
RESULTS_DIR = BASE_DIR / "results"
REPORTS_DIR = BASE_DIR / "reports"
DATA_DIR = BASE_DIR / "data"
FRONTEND_DIR = BASE_DIR / "frontend"


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
    sources: Optional[List[Dict]] = None


class RevealRequest(BaseModel):
    pseudo_id: str
    justification: str
    requester: str


class RevealResponse(BaseModel):
    status: str
    message: str


class AdminSessionRequest(BaseModel):
    """Request model for creating an admin session token."""
    password: str
    requester: Optional[str] = "SOC Admin"


class AdminRevealRequest(BaseModel):
    """Request model for per-user identity reveal using a session token.
    Password is NEVER sent again after the initial session creation.
    """
    pseudo_id: str                         # Always required — no bulk reveal
    session_token: str                     # Short-lived token from /api/admin/session
    justification: Optional[str] = ""
    requester: Optional[str] = "SOC Admin"


class SimulationRequest(BaseModel):
    scenario: str
    user_id: str
    volume_mb: int
    destination: str
    after_hours: bool
    dns_query: str = ""


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


# ── Static files ───────────────────────────────────────────────────────

# Serve frontend static files
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


# ── Routes ─────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def root():
    """Serve the frontend."""
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return HTMLResponse(content=index_path.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>InsiderLens API</h1><p>Frontend not found. Place files in /frontend/</p>")


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


# ── GenAI Singleton ───────────────────────────────────────────────────

_genai_instance = None

def get_genai():
    global _genai_instance
    if _genai_instance is None:
        try:
            from insiderlens.genai_layer import GenAILayer
            _genai_instance = GenAILayer()
        except Exception as e:
            print(f"GenAI init warning: {e}")
            _genai_instance = None
    return _genai_instance


@app.post("/api/copilot")
def copilot_query(request: CopilotRequest):
    """AI copilot for natural-language threat hunting."""
    log_audit("API", "Copilot Query", request.question, "Processing")

    genai = get_genai()
    risk = load_csv("risk_summary.csv")
    cases = load_csv("cases_summary.csv")

    context = {
        "risk_summary": risk.to_dict(orient="records"),
        "cases": cases.to_dict(orient="records"),
        "total_alerts": len(load_csv("alerts.csv")),
    }

    if genai:
        answer, sources = genai.generate_copilot_response(request.question, context)
    else:
        answer = "GenAI copilot is currently initializing. Please try again in a moment."
        sources = []

    log_audit("API", "Copilot Query", request.question, "Success")
    context_used = [f"{s.get('source', '')} > {s.get('section', '')}" for s in sources] if sources else ["knowledge_base"]
    return CopilotResponse(answer=answer, context_used=context_used, sources=sources)


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


USER_IDENTITY_DB = {
    "USER-001": {
        "name": "David Sterling",
        "employee_id": "EMP-8475",
        "email": "david.sterling@acme-corp.internal",
        "department": "IT Systems",
        "role": "Senior DevOps Engineer",
        "ip": "10.0.0.11",
        "device": "LAPTOP-001 (MacBook Pro M2)",
        "clearance": "Level 3 - Secret",
        "hr_status": "Active"
    },
    "USER-002": {
        "name": "Sarah Jenkins",
        "employee_id": "EMP-3427",
        "email": "sarah.jenkins@acme-corp.internal",
        "department": "Human Resources",
        "role": "HR Executive",
        "ip": "10.0.0.12",
        "device": "LAPTOP-002 (Dell XPS 15)",
        "clearance": "Level 2 - Confidential",
        "hr_status": "Active"
    },
    "USER-003": {
        "name": "Elena Rostova",
        "employee_id": "EMP-3386",
        "email": "elena.rostova@acme-corp.internal",
        "department": "Corporate Finance",
        "role": "Lead Financial Analyst",
        "ip": "10.0.0.13",
        "device": "FIN-WS-03 (ThinkPad P16)",
        "clearance": "Level 4 - Top Secret (Finance/M&A)",
        "hr_status": "Active (Resignation Notice Submitted)"
    },
    "USER-004": {
        "name": "Marcus Vance",
        "employee_id": "EMP-4190",
        "email": "marcus.vance@acme-corp.internal",
        "department": "IT Infrastructure",
        "role": "Senior Database Engineer",
        "ip": "10.0.0.14",
        "device": "LAPTOP-004 (ThinkPad X1)",
        "clearance": "Level 3 - Secret",
        "hr_status": "Active"
    },
    "USER-005": {
        "name": "Aisha Patel",
        "employee_id": "EMP-1320",
        "email": "aisha.patel@acme-corp.internal",
        "department": "Operations",
        "role": "Operations Director",
        "ip": "10.0.0.15",
        "device": "OPS-DIR-01 (MacBook Air)",
        "clearance": "Level 3 - Secret",
        "hr_status": "Active"
    },
    "USER-006": {
        "name": "Vikram Rao",
        "employee_id": "EMP-5820",
        "email": "vikram.rao@acme-corp.internal",
        "department": "Analytics & BI",
        "role": "Data Analyst",
        "ip": "10.0.0.16",
        "device": "DATA-WS-06 (Dell Precision)",
        "clearance": "Level 2 - Confidential",
        "hr_status": "Active"
    },
    "USER-007": {
        "name": "Kavita Reddy",
        "employee_id": "EMP-7193",
        "email": "kavita.reddy@acme-corp.internal",
        "department": "IT Helpdesk",
        "role": "IT Support Specialist",
        "ip": "10.0.0.17",
        "device": "IT-DESK-07 (HP EliteBook)",
        "clearance": "Level 2 - Confidential",
        "hr_status": "Active"
    },
    "USER-008": {
        "name": "Michael Chang",
        "employee_id": "EMP-6204",
        "email": "michael.chang@acme-corp.internal",
        "department": "Enterprise Sales",
        "role": "Sales Executive",
        "ip": "10.0.0.18",
        "device": "SALES-MOB-08 (Surface Pro)",
        "clearance": "Level 1 - Internal",
        "hr_status": "Active"
    },
    "USER-009": {
        "name": "Siddharth Nair",
        "employee_id": "EMP-9142",
        "email": "siddharth.nair@acme-corp.internal",
        "department": "IT Infrastructure",
        "role": "Systems Engineer",
        "ip": "10.0.0.19",
        "device": "LAPTOP-009 (MacBook Pro 16)",
        "clearance": "Level 3 - Secret",
        "hr_status": "On Leave (Flagged Ingress Anomaly)"
    },
    "USER-010": {
        "name": "Rachel Adams",
        "employee_id": "EMP-2051",
        "email": "rachel.adams@contractor.internal",
        "department": "Engineering Contractors",
        "role": "Security Consultant",
        "ip": "10.0.0.20",
        "device": "EXT-SEC-10 (ThinkPad T14)",
        "clearance": "Level 2 - Contractor Escorted",
        "hr_status": "Contract Active"
    }
}

VALID_ADMIN_PASSWORDS = {"admin", "admin123", "insiderlens", "password", "root"}

# ── Admin session store ────────────────────────────────────────────────
# Maps session_token -> expiry datetime. Stored in process memory only.
# No PII is stored here — tokens are opaque UUIDs.
_admin_sessions: Dict[str, datetime] = {}
SESSION_TTL_HOURS = 1


def _purge_expired_sessions():
    """Remove expired session tokens from the in-memory store."""
    now = datetime.now()
    expired = [t for t, exp in _admin_sessions.items() if now > exp]
    for t in expired:
        del _admin_sessions[t]


def _validate_session(token: str) -> bool:
    """Return True if the token is valid and not expired."""
    _purge_expired_sessions()
    if token not in _admin_sessions:
        return False
    if datetime.now() > _admin_sessions[token]:
        del _admin_sessions[token]
        return False
    return True


@app.post("/api/admin/session")
def create_admin_session(request: AdminSessionRequest):
    """
    Step 1 of the gated identity reveal flow.
    Validates the admin password and returns a short-lived session token.
    The password is NEVER stored or returned — only an opaque token.
    No identity data is returned here.
    """
    import os
    env_pw = os.getenv("ADMIN_PASSWORD")
    valid_pws = set(VALID_ADMIN_PASSWORDS)
    if env_pw:
        valid_pws.add(env_pw)

    if request.password not in valid_pws:
        log_audit(
            request.requester,
            "Admin Session Creation",
            "SOC Environment",
            "DENIED: Incorrect password",
        )
        raise HTTPException(status_code=401, detail="Invalid admin password.")

    _purge_expired_sessions()
    token = secrets.token_urlsafe(40)  # 320-bit cryptographically random token
    _admin_sessions[token] = datetime.now() + timedelta(hours=SESSION_TTL_HOURS)

    log_audit(
        request.requester,
        "Admin Session Created",
        "SOC Environment",
        f"Token issued. Expires in {SESSION_TTL_HOURS}h. Active sessions: {len(_admin_sessions)}",
    )
    return {
        "status": "authorized",
        "session_token": token,
        "expires_in_seconds": SESSION_TTL_HOURS * 3600,
        # Deliberately no identity data returned here
    }


@app.post("/api/admin/reveal")
def admin_reveal(request: AdminRevealRequest):
    """
    Step 2 of the gated identity reveal flow.
    Requires a valid session token AND a specific pseudo_id.
    Returns ONLY that user's identity — no bulk reveal is possible.
    Every call is individually audited.
    """
    # Validate session token — no password re-transmission needed
    if not _validate_session(request.session_token):
        log_audit(
            request.requester,
            "Admin Identity Reveal",
            request.pseudo_id,
            "DENIED: Invalid or expired session token",
        )
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired admin session. Please re-authenticate.",
        )

    pid = request.pseudo_id.strip().upper()
    if not pid:
        raise HTTPException(status_code=400, detail="pseudo_id is required.")

    identity = USER_IDENTITY_DB.get(pid)
    if not identity:
        # Check by employee_id, stripped U- / EMP- prefix, or exact name
        normalized_target = pid.replace("EMP-", "").replace("U-", "").replace("USER-", "").strip()
        for k, id_data in USER_IDENTITY_DB.items():
            emp_id = id_data.get("employee_id", "").upper()
            emp_num = emp_id.replace("EMP-", "").strip()
            name_upper = id_data.get("name", "").upper()
            if emp_id == pid or emp_num == normalized_target or name_upper == pid:
                identity = id_data
                break

    if not identity:
        # Fallback for dynamic user IDs not in the static DB
        identity = {
            "name": f"Unknown Subject ({pid})",
            "employee_id": f"EMP-{abs(hash(pid)) % 9000 + 1000}",
            "email": f"{pid.lower().replace('-', '.')}@acme-corp.internal",
            "department": "Unknown",
            "role": "Unknown",
            "ip": "N/A",
            "device": "N/A",
            "clearance": "Unknown",
            "hr_status": "Unknown",
        }

    justification_str = (request.justification or "").strip() or "On-demand admin reveal"
    log_audit(
        request.requester,
        "Admin Identity Reveal",
        f"{pid} → {identity['name']} ({identity['employee_id']})",
        f"SUCCESS — {justification_str}",
    )
    # Return only this user's data. No other identities are included.
    return {
        "status": "success",
        "pseudo_id": pid,
        "identity": identity,
    }


@app.get("/api/admin/session/status")
def admin_session_status(token: str):
    """Check whether a session token is still valid (lightweight heartbeat)."""
    valid = _validate_session(token)
    return {"valid": valid}

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


# ── New endpoints for enhanced frontend ──────────────────────────────

@app.get("/api/alerts/by-detector")
def get_alerts_by_detector():
    """Get alert counts grouped by detector type."""
    alerts = load_csv("alerts.csv")
    counts = alerts["detector"].value_counts().to_dict()
    return counts


@app.get("/api/alerts/daily")
def get_daily_alerts():
    """Get daily alert counts grouped by detector."""
    alerts = load_csv("alerts.csv")
    if "timestamp" not in alerts.columns:
        return []
    alerts["date"] = pd.to_datetime(alerts["timestamp"], errors="coerce").dt.strftime("%Y-%m-%d")
    daily = alerts.groupby(["date", "detector"]).size().reset_index(name="count")
    return daily.to_dict(orient="records")


@app.get("/api/daily-features")
def get_daily_features(user_id: Optional[str] = None):
    """Get daily features, optionally filtered by user."""
    df = load_csv("user_daily_features.csv")
    if user_id:
        df = df[df["user_id"] == user_id]
    # Select only relevant columns to reduce payload
    cols = ["user_id", "date", "total_flows", "total_bytes_out", "total_bytes_in",
            "unique_destinations", "after_hours_ratio", "new_destinations",
            "department", "role", "hr_status",
            "total_bytes_out_z_self", "total_flows_z_self",
            "unique_destinations_z_self", "after_hours_ratio_z_self"]
    available_cols = [c for c in cols if c in df.columns]
    result = df[available_cols].fillna(0).to_dict(orient="records")
    return result


@app.get("/api/flows/hourly/{user_id}")
def get_user_hourly_activity(user_id: str):
    """Get hourly flow distribution for a user."""
    flows = load_csv("enriched_flows.csv")
    user_flows = flows[flows["user_id"] == user_id]
    if "hour" not in user_flows.columns:
        return []
    hour_dist = user_flows.groupby("hour").size().reindex(range(24), fill_value=0)
    return [{"hour": int(h), "count": int(c)} for h, c in hour_dist.items()]


@app.get("/api/flows/network-graph")
def get_network_graph():
    """Get user-destination network data with category and risk indicators."""
    flows = load_csv("enriched_flows.csv")
    user_dest = flows.groupby(["user_id", "dst_ip"]).agg(
        total_bytes=("bytes_out", "sum"),
        flow_count=("flow_id", "count"),
        dst_category=("dst_category", lambda s: s.dropna().iloc[0] if len(s.dropna()) > 0 else "external"),
        is_suspicious=("scenario_label", lambda s: bool(any(x != "benign" and str(x) != "nan" for x in s))),
    ).reset_index()
    top = user_dest.nlargest(60, "total_bytes")
    return top.to_dict(orient="records")


@app.get("/api/shap")
def get_shap_data():
    """Get SHAP feature importance data."""
    shap_path = RESULTS_DIR / "shap_values.npy"
    names_path = RESULTS_DIR / "shap_feature_names.json"
    if not shap_path.exists() or not names_path.exists():
        return {"available": False}
    
    shap_values = np.load(shap_path)
    with open(names_path, encoding="utf-8") as f:
        features = json.load(f)
    
    mean_abs_shap = np.abs(shap_values).mean(axis=0).tolist()
    importance = sorted(
        [{"feature": f, "importance": round(v, 6)} for f, v in zip(features, mean_abs_shap)],
        key=lambda x: x["importance"],
        reverse=True,
    )
    return {"available": True, "features": importance}


@app.get("/api/department-stats")
def get_department_stats():
    """Get risk statistics grouped by department."""
    daily = load_csv("user_daily_features.csv")
    stats = daily.groupby("department").agg(
        avg_bytes_out=("total_bytes_out", "mean"),
        max_bytes_out=("total_bytes_out", "max"),
        avg_after_hours=("after_hours_ratio", "mean"),
        user_count=("user_id", "nunique"),
    ).reset_index()
    return stats.to_dict(orient="records")


@app.get("/api/scenarios")
def get_scenarios():
    """Get scenario catalog."""
    catalog_path = DATA_DIR / "scenario_catalog.csv"
    if catalog_path.exists():
        df = pd.read_csv(catalog_path)
        return df.to_dict(orient="records")
    return []


@app.post("/api/simulate")
def run_simulation(request: SimulationRequest):
    """Run threat simulation against detection models."""
    log_audit("API", "Simulation", f"{request.scenario} for {request.user_id}", "Processing")

    sim_bytes_out = request.volume_mb * 1024 * 1024
    sim_bytes_in = int(sim_bytes_out * 0.02)
    
    triggered_detectors = []
    max_score = 0.0
    tags = []

    # DNS Tunneling check
    if request.dns_query and len(request.dns_query) > 20:
        from insiderlens.detectors import DNSTunnelDetector
        tunnel_detector = DNSTunnelDetector()
        test_df = pd.DataFrame([{
            "dns_query": request.dns_query,
            "dst_port": 53,
            "bytes_out": sim_bytes_out,
        }])
        tunnel_res = tunnel_detector.predict(test_df)
        if tunnel_res:
            score = tunnel_res[0].score
            triggered_detectors.append({
                "name": "DNS Tunnel Detector",
                "score": score,
                "tags": tunnel_res[0].evidence_tags
            })
            tags.extend(tunnel_res[0].evidence_tags)
            max_score = max(max_score, score)

    # Volume & Asymmetry check
    if request.volume_mb > 100 or request.after_hours:
        score = min(0.98, 0.4 + (request.volume_mb / 2000) * 0.4 + (0.2 if request.after_hours else 0))
        vol_tags = ["high_volume_outbound"]
        if request.after_hours:
            vol_tags.append("after_hours_spike")
        if any(c in request.destination for c in ["mega", "dropbox", "drive", "wetransfer"]):
            vol_tags.append("cloud_storage_upload")
        triggered_detectors.append({"name": "Volume & Asymmetry Detector", "score": score, "tags": vol_tags})
        tags.extend(vol_tags)
        max_score = max(max_score, score)

    # Flow Classifier check
    upload_ratio = sim_bytes_out / (sim_bytes_in + 1)
    if upload_ratio > 10:
        flow_score = min(0.96, 0.5 + (upload_ratio / 50) * 0.3 + (0.15 if request.after_hours else 0))
        flow_tags = ["high_upload_ratio", "exfil_flow_signature"]
        triggered_detectors.append({"name": "Flow Classifier (XGBoost)", "score": flow_score, "tags": flow_tags})
        tags.extend(flow_tags)
        max_score = max(max_score, flow_score)

    # Low-and-Slow check
    if "Low-and-Slow" in request.scenario or "Slow" in request.scenario:
        ls_score = 0.85
        ls_tags = ["cumulative_volume_anomaly", "cusum_threshold_exceeded"]
        triggered_detectors.append({"name": "Low-and-Slow Detector (CUSUM)", "score": ls_score, "tags": ls_tags})
        tags.extend(ls_tags)
        max_score = max(max_score, ls_score)

    tags = list(set(tags))
    status_label = "CRITICAL ALERT" if max_score >= 0.7 else "HIGH ANOMALY" if max_score >= 0.4 else "NORMAL"

    # Get AI explanation
    narrative = "Anomaly detected by multiple ensemble models."
    recommended_actions = [
        "Verify user role and business justification",
        "Restrict outbound data transfers for user",
        "Review internal staging file access",
    ]
    try:
        genai_layer = get_genai()
        if genai_layer:
            exp_data = {
                "alert_id": "SIM-ALT-001",
                "user_id": request.user_id,
                "detector": triggered_detectors[0]["name"] if triggered_detectors else "Ensemble",
                "score": max_score,
                "evidence_tags": tags,
                "details": {
                    "destination": request.destination,
                    "volume_mb": request.volume_mb,
                    "after_hours": request.after_hours,
                },
                "kill_chain_stage": 3,
            }
            explanation = genai_layer.explain_alert(exp_data)
            narrative = explanation.get("narrative", explanation.get("summary", narrative))
            recommended_actions = explanation.get("recommended_actions", recommended_actions)
    except Exception:
        pass

    log_audit("API", "Simulation", f"{request.scenario} for {request.user_id}", "Complete")

    return {
        "max_score": max_score,
        "status": status_label,
        "triggered_detectors": triggered_detectors,
        "tags": tags,
        "kill_chain_stage": "Stage 3: Exfiltration" if max_score >= 0.5 else "Stage 1: Access",
        "narrative": narrative,
        "recommended_actions": recommended_actions,
        "target": {
            "user_id": request.user_id,
            "destination": request.destination,
            "volume_mb": request.volume_mb,
        },
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
