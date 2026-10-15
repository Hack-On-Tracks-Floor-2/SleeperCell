import json
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from pipeline.db import get_connection
from pipeline.pseudonymize import get_pseudonymizer

app = FastAPI(
    title="InsiderLens API",
    description="Cybersecurity SOC API for encrypted behavioral insider threat detection",
    version="0.1.0-push1"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    database: str
    timestamp: str

class AlertModel(BaseModel):
    alert_id: str
    ts: str
    user_pid: str
    detector: str
    score: float
    evidence_tags: List[str]
    top_features: Dict[str, Any]
    stage: str
    case_id: Optional[str]

class CaseSummary(BaseModel):
    case_id: str
    user_pid: str
    first_seen: str
    last_seen: str
    risk_score: float
    band: str
    stages: List[str]
    status: str

class CaseDetail(BaseModel):
    case: CaseSummary
    alerts: List[AlertModel]
    verdict: Optional[Dict[str, Any]]
    narrative: Optional[Dict[str, Any]]
    context_entries: List[Dict[str, Any]]

class RevealRequest(BaseModel):
    user_pid: str
    actor: str
    role: str = Field(description="Must be 'Auditor', 'SecurityAdmin', or 'SOC_Lead'")
    justification: str = Field(min_length=10, description="Audit reason for identity de-anonymization")

class RevealResponse(BaseModel):
    success: bool
    user_pid: str
    real_name: Optional[str] = None
    message: str

@app.get("/health", response_model=HealthResponse)
def health():
    try:
        con = get_connection(read_only=True)
        count = con.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
        con.close()
        db_status = f"healthy ({count} cases)"
    except Exception as e:
        db_status = f"error: {str(e)}"

    return HealthResponse(
        status="ok",
        service="insiderlens",
        version="0.1.0-push1",
        database=db_status,
        timestamp=datetime.now(timezone.utc).isoformat()
    )

@app.get("/alerts", response_model=List[AlertModel])
def get_alerts(
    since: Optional[str] = None,
    user_pid: Optional[str] = None,
    detector: Optional[str] = None,
    limit: int = Query(default=100, le=1000)
):
    con = get_connection(read_only=True)
    query = "SELECT alert_id, ts, user_pid, detector, score, evidence_tags, top_features, stage, case_id FROM alerts WHERE 1=1"
    params = []

    if since:
        query += " AND ts >= ?"
        params.append(since)
    if user_pid:
        query += " AND user_pid = ?"
        params.append(user_pid)
    if detector:
        query += " AND detector = ?"
        params.append(detector)

    query += " ORDER BY ts DESC LIMIT ?"
    params.append(limit)

    rows = con.execute(query, params).fetchall()
    con.close()

    results = []
    for r in rows:
        results.append(AlertModel(
            alert_id=r[0],
            ts=str(r[1]),
            user_pid=r[2],
            detector=r[3],
            score=float(r[4]),
            evidence_tags=json.loads(r[5]) if r[5] else [],
            top_features=json.loads(r[6]) if r[6] else {},
            stage=r[7],
            case_id=r[8]
        ))
    return results

@app.get("/cases", response_model=List[CaseSummary])
def get_cases():
    con = get_connection(read_only=True)
    rows = con.execute(
        "SELECT case_id, user_pid, first_seen, last_seen, risk_score, band, stages, status FROM cases ORDER BY risk_score DESC"
    ).fetchall()
    con.close()

    cases = []
    for r in rows:
        stages_list = [s.strip() for s in r[6].split(",") if s.strip()] if r[6] else []
        cases.append(CaseSummary(
            case_id=r[0],
            user_pid=r[1],
            first_seen=str(r[2]),
            last_seen=str(r[3]),
            risk_score=float(r[4]),
            band=r[5],
            stages=stages_list,
            status=r[7]
        ))
    return cases

@app.get("/cases/{case_id}", response_model=CaseDetail)
def get_case_detail(case_id: str):
    con = get_connection(read_only=True)
    
    # 1. Case Header
    case_row = con.execute(
        "SELECT case_id, user_pid, first_seen, last_seen, risk_score, band, stages, status FROM cases WHERE case_id = ?",
        [case_id]
    ).fetchone()
    
    if not case_row:
        con.close()
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
        
    stages_list = [s.strip() for s in case_row[6].split(",") if s.strip()] if case_row[6] else []
    case_summary = CaseSummary(
        case_id=case_row[0],
        user_pid=case_row[1],
        first_seen=str(case_row[2]),
        last_seen=str(case_row[3]),
        risk_score=float(case_row[4]),
        band=case_row[5],
        stages=stages_list,
        status=case_row[7]
    )

    # 2. Associated Alerts
    alert_rows = con.execute(
        "SELECT alert_id, ts, user_pid, detector, score, evidence_tags, top_features, stage, case_id FROM alerts WHERE case_id = ? ORDER BY ts ASC",
        [case_id]
    ).fetchall()
    alerts = []
    for r in alert_rows:
        alerts.append(AlertModel(
            alert_id=r[0],
            ts=str(r[1]),
            user_pid=r[2],
            detector=r[3],
            score=float(r[4]),
            evidence_tags=json.loads(r[5]) if r[5] else [],
            top_features=json.loads(r[6]) if r[6] else {},
            stage=r[7],
            case_id=r[8]
        ))

    # 3. Agent Verdict
    v_row = con.execute(
        "SELECT verdict, priority_delta, reasoning, evidence_ids, confidence, model_band, final_band FROM case_verdicts WHERE case_id = ?",
        [case_id]
    ).fetchone()
    verdict = None
    if v_row:
        verdict = {
            "verdict": v_row[0],
            "priority_delta": v_row[1],
            "reasoning": v_row[2],
            "evidence_ids": json.loads(v_row[3]) if v_row[3] else [],
            "confidence": v_row[4],
            "model_band": v_row[5],
            "final_band": v_row[6]
        }

    # 4. Verified Narrative
    n_row = con.execute(
        "SELECT text, verified_pct, unverified_sentences FROM narratives WHERE case_id = ?",
        [case_id]
    ).fetchone()
    narrative = None
    if n_row:
        narrative = {
            "text": n_row[0],
            "verified_pct": float(n_row[1]),
            "unverified_sentences": json.loads(n_row[2]) if n_row[2] else []
        }

    # 5. User Context Entries
    ctx_rows = con.execute(
        "SELECT context_id, subject, type, start, \"end\", expected_destinations, expected_volume_mb, source_ticket_id FROM context WHERE subject = ?",
        [case_summary.user_pid]
    ).fetchall()
    context_entries = []
    for cr in ctx_rows:
        context_entries.append({
            "context_id": cr[0],
            "subject": cr[1],
            "type": cr[2],
            "start": str(cr[3]),
            "end": str(cr[4]),
            "expected_destinations": cr[5],
            "expected_volume_mb": cr[6],
            "source_ticket_id": cr[7]
        })

    con.close()

    return CaseDetail(
        case=case_summary,
        alerts=alerts,
        verdict=verdict,
        narrative=narrative,
        context_entries=context_entries
    )

@app.post("/privacy/reveal", response_model=RevealResponse)
def reveal_identity(req: RevealRequest):
    pseudonymizer = get_pseudonymizer()
    success, result = pseudonymizer.reveal(
        user_pid=req.user_pid,
        actor=req.actor,
        role=req.role,
        justification=req.justification
    )
    if not success:
        return RevealResponse(
            success=False,
            user_pid=req.user_pid,
            real_name=None,
            message=result
        )
    return RevealResponse(
        success=True,
        user_pid=req.user_pid,
        real_name=result,
        message="Identity de-anonymized. Action recorded to compliance audit log."
    )

@app.get("/audit")
def get_audit_log(limit: int = 50):
    con = get_connection(read_only=True)
    rows = con.execute(
        "SELECT ts, actor, role, action, target, justification, result FROM audit ORDER BY ts DESC LIMIT ?",
        [limit]
    ).fetchall()
    con.close()

    return [
        {
            "ts": str(r[0]),
            "actor": r[1],
            "role": r[2],
            "action": r[3],
            "target": r[4],
            "justification": r[5],
            "result": r[6]
        }
        for r in rows
    ]

@app.get("/users")
def get_users():
    con = get_connection(read_only=True)
    rows = con.execute(
        """
        SELECT user_pid, dept, role, 
               SUM(bytes_out_total) as total_bytes, 
               AVG(upload_ratio) as avg_upload_ratio,
               MAX(cum_out_30d) as max_30d
        FROM user_features_daily 
        GROUP BY user_pid, dept, role
        """
    ).fetchall()
    con.close()
    return [
        {
            "user_pid": r[0],
            "dept": r[1],
            "role": r[2],
            "total_bytes_mb": round(r[3] / (1024 * 1024), 2) if r[3] else 0.0,
            "avg_upload_ratio": round(r[4], 3) if r[4] else 0.0,
            "max_30d_mb": round(r[5] / (1024 * 1024), 2) if r[5] else 0.0
        }
        for r in rows
    ]
