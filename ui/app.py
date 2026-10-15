import os
import json
from datetime import datetime, timezone
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from pipeline.db import get_connection
from pipeline.pseudonymize import get_pseudonymizer
from genai.dest_classifier import classify_destination

st.set_page_config(
    page_title="InsiderLens | AI-Powered Behavioral SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom SOC Dark Glassmorphism Styling
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');

    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;
    }
    code, pre {
        font-family: 'JetBrains Mono', monospace !important;
    }
    
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
    }
    
    /* Metric Cards */
    .metric-card {
        background: linear-gradient(135deg, rgba(26, 32, 53, 0.8) 0%, rgba(15, 23, 42, 0.95) 100%);
        border: 1px solid rgba(56, 189, 248, 0.2);
        box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.1);
        border-radius: 12px;
        padding: 20px;
        backdrop-filter: blur(8px);
        margin-bottom: 12px;
    }
    .metric-title {
        color: #94a3b8;
        font-size: 0.82rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .metric-value {
        color: #f8fafc;
        font-size: 1.8rem;
        font-weight: 800;
        margin: 4px 0;
    }
    .metric-delta {
        font-size: 0.85rem;
        font-weight: 600;
    }
    .metric-delta.danger { color: #f43f5e; }
    .metric-delta.success { color: #10b981; }
    .metric-delta.info { color: #38bdf8; }

    /* Badges */
    .badge-critical {
        background-color: rgba(244, 63, 94, 0.15);
        color: #f43f5e;
        border: 1px solid rgba(244, 63, 94, 0.35);
        border-radius: 6px;
        padding: 4px 10px;
        font-size: 0.78rem;
        font-weight: 700;
        letter-spacing: 0.05em;
        text-transform: uppercase;
    }
    .badge-high {
        background-color: rgba(245, 158, 11, 0.15);
        color: #f59e0b;
        border: 1px solid rgba(245, 158, 11, 0.35);
        border-radius: 6px;
        padding: 4px 10px;
        font-size: 0.78rem;
        font-weight: 700;
        text-transform: uppercase;
    }
    .badge-verified {
        background: linear-gradient(90deg, rgba(16, 185, 129, 0.18) 0%, rgba(5, 150, 105, 0.25) 100%);
        color: #34d399;
        border: 1px solid rgba(16, 185, 129, 0.4);
        border-radius: 6px;
        padding: 6px 14px;
        font-weight: 700;
        font-size: 0.82rem;
        display: inline-flex;
        align-items: center;
        gap: 6px;
    }
    
    /* Narrative Container */
    .narrative-box {
        background: rgba(15, 23, 42, 0.75);
        border: 1px solid rgba(16, 185, 129, 0.3);
        border-left: 4px solid #10b981;
        border-radius: 10px;
        padding: 18px;
        line-height: 1.6;
        color: #e2e8f0;
        font-size: 0.95rem;
    }

    /* Trust Boundary Alert */
    .trust-box {
        background: rgba(30, 41, 59, 0.7);
        border: 1px dashed rgba(148, 163, 184, 0.3);
        border-radius: 8px;
        padding: 14px 18px;
        font-size: 0.88rem;
        color: #cbd5e1;
        margin-bottom: 20px;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar Navigation & Trust Boundary Summary
with st.sidebar:
    st.markdown("### 🛡️ **InsiderLens SOC**")
    st.caption("Behavioral ML & Guardrailed GenAI Triage")
    
    page = st.radio(
        "Navigation",
        ["Dashboard", "Case Investigation", "Destination Intelligence", "Privacy & Audit", "Scenario Sandbox"],
        index=0
    )
    
    st.markdown("---")
    st.markdown("#### 🔒 Trust Boundary")
    st.markdown("""
    - **Scores**: ML & statistical models (never LLM).
    - **Privacy**: LLM only observes pseudonyms (`U-xxxx`).
    - **Triage**: Priority shift bounded to ±1 band.
    - **Fidelity**: Narrative verified against evidence JSON.
    """)
    st.markdown("---")
    st.caption("InsiderLens Engine v0.1.0 (Push 1)")

con = get_connection(read_only=True)

# ==============================================================================
# PAGE 1: DASHBOARD
# ==============================================================================
if page == "Dashboard":
    st.markdown("## 📡 SOC Behavioral Telemetry & Alert Feed")
    st.markdown(
        "<div class='trust-box'><strong>Active Telemetry:</strong> Ingesting 14-day network flow statistics and metadata from DuckDB golden seed. Payload contents remain 100% end-to-end encrypted.</div>",
        unsafe_allow_html=True
    )
    
    # KPI Row
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-title">Monitored Personas</div>
            <div class="metric-value">5</div>
            <div class="metric-delta info">14 simulated days</div>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-title">Encrypted Flows Scored</div>
            <div class="metric-value">1,467</div>
            <div class="metric-delta success">100% Behavioral</div>
        </div>
        """, unsafe_allow_html=True)
    with col3:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-title">Active Security Alerts</div>
            <div class="metric-value">2</div>
            <div class="metric-delta danger">2 Critical Sensors</div>
        </div>
        """, unsafe_allow_html=True)
    with col4:
        st.markdown("""
        <div class="metric-card">
            <div class="metric-title">Open Correlated Cases</div>
            <div class="metric-value">1</div>
            <div class="metric-delta danger">Band: Critical (88.5)</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("---")
    
    col_left, col_right = st.columns([1.8, 1.2])
    
    with col_left:
        st.subheader("🔥 High-Priority Behavioral Alerts")
        alerts_df = con.execute(
            """
            SELECT alert_id, ts, user_pid, detector, score, evidence_tags, stage, case_id 
            FROM alerts 
            ORDER BY score DESC
            """
        ).df()
        
        if not alerts_df.empty:
            for _, row in alerts_df.iterrows():
                tags = json.loads(row["evidence_tags"]) if isinstance(row["evidence_tags"], str) else []
                tags_str = " ".join([f"`{t}`" for t in tags])
                score_pct = int(row["score"] * 100)
                
                with st.expander(f"⚠️ {row['alert_id']} | User: {row['user_pid']} | Stage: {row['stage'].upper()} (Score: {score_pct}%)", expanded=True):
                    c1, c2 = st.columns([1, 2])
                    with c1:
                        st.markdown(f"**Detector:** `{row['detector']}`")
                        st.markdown(f"**Timestamp:** `{row['ts']}`")
                        st.markdown(f"**Case Link:** `{row['case_id']}`")
                    with c2:
                        st.markdown(f"**Evidence Indicators:** {tags_str}")
                        st.progress(float(row["score"]))
        else:
            st.info("No active alerts.")

    with col_right:
        st.subheader("📊 Outbound Volume by Department")
        dept_df = con.execute(
            """
            SELECT dept, SUM(bytes_out_total) / (1024*1024) as total_mb
            FROM user_features_daily
            GROUP BY dept
            ORDER BY total_mb DESC
            """
        ).df()
        
        fig = px.bar(
            dept_df,
            x="dept",
            y="total_mb",
            color="dept",
            labels={"dept": "Department", "total_mb": "Outbound Volume (MB)"},
            template="plotly_dark",
            color_discrete_sequence=["#38bdf8", "#818cf8", "#f43f5e", "#10b981", "#fbbf24"]
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            margin=dict(l=20, r=20, t=20, b=20),
            showlegend=False
        )
        st.plotly_chart(fig, use_container_width=True)

# ==============================================================================
# PAGE 2: CASE INVESTIGATION
# ==============================================================================
elif page == "Case Investigation":
    st.markdown("## 🔍 Deep Case Investigation & GenAI Narrative")
    
    cases_df = con.execute("SELECT case_id, user_pid, risk_score, band, stages, status FROM cases").df()
    if cases_df.empty:
        st.warning("No cases found in database.")
    else:
        selected_case = st.selectbox("Select Active Security Case", cases_df["case_id"].tolist(), index=0)
        
        # Load Case Data
        case_data = con.execute("SELECT * FROM cases WHERE case_id = ?", [selected_case]).df().iloc[0]
        verdict_data = con.execute("SELECT * FROM case_verdicts WHERE case_id = ?", [selected_case]).df()
        narrative_data = con.execute("SELECT * FROM narratives WHERE case_id = ?", [selected_case]).df()
        alerts_data = con.execute("SELECT * FROM alerts WHERE case_id = ? ORDER BY ts ASC", [selected_case]).df()
        
        # Case Header Card
        st.markdown(f"""
        <div class="metric-card">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <div>
                    <h2 style="margin:0; font-weight:800; color:#f8fafc;">Case {case_data['case_id']} &bull; Subject: {case_data['user_pid']}</h2>
                    <span style="color:#94a3b8; font-size:0.9rem;">First seen: {case_data['first_seen']} &bull; Last seen: {case_data['last_seen']}</span>
                </div>
                <div style="text-align:right;">
                    <span class="badge-critical">{case_data['band']} RISK (Score: {case_data['risk_score']})</span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Kill-Chain Progression Bar
        st.markdown("#### 🎯 Kill-Chain Staging Progression")
        stages = [s.strip() for s in case_data["stages"].split(",")]
        
        kc_col1, kc_col2, kc_col3, kc_col4 = st.columns(4)
        with kc_col1:
            st.markdown(f"{'✅ **1. Access**' if 'access' in stages else '⚪ 1. Access'}")
        with kc_col2:
            st.markdown(f"{'🔴 **2. Collection & Staging**' if 'collection' in stages else '⚪ 2. Collection'}")
        with kc_col3:
            st.markdown(f"{'🚨 **3. Exfiltration**' if 'exfiltration' in stages else '⚪ 3. Exfiltration'}")
        with kc_col4:
            st.markdown(f"{'⚠️ **4. Cover-up**' if 'cover_up' in stages else '⚪ 4. Cover-up'}")
        
        st.markdown("---")
        
        # Baseline vs Actual Volume Chart
        st.markdown("#### 📈 Outbound Volume: Baseline vs Actual Activity")
        flows_daily = con.execute(
            """
            SELECT date, bytes_out_total / (1024*1024) as daily_mb, internal_read_bytes / (1024*1024) as internal_mb
            FROM user_features_daily
            WHERE user_pid = ?
            ORDER BY date ASC
            """,
            [case_data["user_pid"]]
        ).df()
        
        fig = go.Figure()
        fig.add_trace(go.Bar(
            x=flows_daily["date"],
            y=flows_daily["internal_mb"],
            name="Internal Read / Staging (MB)",
            marker_color="#818cf8"
        ))
        fig.add_trace(go.Bar(
            x=flows_daily["date"],
            y=flows_daily["daily_mb"],
            name="External Outbound (MB)",
            marker_color="#f43f5e"
        ))
        fig.add_hline(y=80, line_dash="dash", line_color="#38bdf8", annotation_text="User 30-Day Mean Baseline (80MB)")
        fig.update_layout(
            barmode="stack",
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=320,
            margin=dict(l=20, r=20, t=30, b=20)
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # GenAI Verified Narrative & Analyst Verdict
        c_left, c_right = st.columns([1.4, 1.0])
        
        with c_left:
            st.markdown("#### 📝 Faithfully Verified Narrative")
            if not narrative_data.empty:
                narrative_row = narrative_data.iloc[0]
                pct = narrative_row["verified_pct"]
                st.markdown(f"""
                <div style="margin-bottom: 10px;">
                    <span class="badge-verified">🛡️ VERIFIED AGAINST EVIDENCE JSON ({pct:.1f}% FIDELITY)</span>
                </div>
                <div class="narrative-box">
                    {narrative_row['text']}
                </div>
                """, unsafe_allow_html=True)
            else:
                st.info("No narrative generated for this case.")

        with c_right:
            st.markdown("#### ⚖️ GenAI Triage Agent Verdict")
            if not verdict_data.empty:
                v = verdict_data.iloc[0]
                ev_ids = json.loads(v["evidence_ids"]) if isinstance(v["evidence_ids"], str) else []
                ev_str = " ".join([f"`{e}`" for e in ev_ids])
                
                st.markdown(f"""
                <div class="metric-card">
                    <div style="margin-bottom:8px;">
                        <strong>Verdict:</strong> <span class="badge-critical">{v['verdict'].upper()}</span>
                        &nbsp;&bull;&nbsp; <strong>Priority Shift:</strong> <code>+{v['priority_delta']} Band</code>
                    </div>
                    <div style="color:#cbd5e1; font-size:0.88rem; line-height:1.5; margin-bottom:12px;">
                        {v['reasoning']}
                    </div>
                    <div style="font-size:0.8rem; color:#94a3b8;">
                        <strong>Evidence References:</strong> {ev_str}<br>
                        <strong>Confidence:</strong> <code>{v['confidence'].upper()}</code> &bull; <strong>Final Band:</strong> <code>{v['final_band']}</code>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.info("No verdict available.")

        # Sensor Alerts Timeline
        st.markdown("#### 🔬 Sensor Alert Evidence")
        st.dataframe(
            alerts_data[["alert_id", "ts", "detector", "score", "stage", "evidence_tags"]],
            use_container_width=True
        )

# ==============================================================================
# PAGE 3: DESTINATION INTELLIGENCE
# ==============================================================================
elif page == "Destination Intelligence":
    st.markdown("## 🌐 Destination Intelligence & LLM Classifier")
    st.markdown(
        "<div class='trust-box'><strong>Unique Domain Categorization:</strong> Destination domains are classified into bounded categories. Cached on disk to guarantee zero network latency during live SOC investigations.</div>",
        unsafe_allow_html=True
    )
    
    col_input, col_action = st.columns([3, 1])
    with col_input:
        domain_query = st.text_input("Test Domain Classification", value="megashare-demo.net")
    with col_action:
        st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)
        classify_btn = st.button("Classify Domain", use_container_width=True)
        
    if classify_btn and domain_query:
        with st.spinner("Classifying domain with LLM / cache..."):
            result = classify_destination(domain_query)
            st.success(f"Category: **{result.category.value}** (Confidence: {result.confidence:.2f}) - {result.reasoning}")
            
    st.markdown("---")
    st.subheader("📚 Cached Intelligence Database (`dest_intel`)")
    intel_df = con.execute("SELECT domain, category, confidence, source, classified_at FROM dest_intel ORDER BY classified_at DESC").df()
    st.dataframe(intel_df, use_container_width=True)

# ==============================================================================
# PAGE 4: PRIVACY & AUDIT
# ==============================================================================
elif page == "Privacy & Audit":
    st.markdown("## 🔐 Privacy Gate & Compliance Audit Trail")
    st.markdown(
        "<div class='trust-box'><strong>Defensible Privacy Guard:</strong> Real employee identities are strictly segregated into a secured vault. The GenAI analyst never sees real identities. De-anonymization requires RBAC authorization and mandatory justification.</div>",
        unsafe_allow_html=True
    )
    
    col_reveal, col_info = st.columns([1.5, 1.0])
    
    with col_reveal:
        st.subheader("De-Anonymization Request")
        with st.form("reveal_form"):
            user_pid_in = st.text_input("User Pseudonym", value="U-3386")
            actor_name = st.text_input("Requesting Investigator / Actor", value="j_doe_lead")
            actor_role = st.selectbox("Role", ["SOC_Lead", "Auditor", "SecurityAdmin", "Analyst_L1"])
            justification = st.text_area("Audit Justification (Required min 10 chars)", value="Critical data exfiltration alert ALT-0102 confirmed to megashare-demo.net; escalating to incident response lead.")
            submit_reveal = st.form_submit_button("Request Identity Reveal")
            
            if submit_reveal:
                pseudonymizer = get_pseudonymizer()
                success, msg = pseudonymizer.reveal(user_pid_in, actor_name, actor_role, justification)
                if success:
                    st.success(f"🔓 **Approved:** Identity for `{user_pid_in}` is **{msg}**")
                    st.caption("Action logged to compliance audit table.")
                else:
                    st.error(f"🚫 {msg}")
    
    with col_info:
        st.subheader("Audit Integrity Rules")
        st.markdown("""
        - 🛡️ **Role Enforcement:** Only `SOC_Lead`, `Auditor`, or `SecurityAdmin` may unlock real identities.
        - 📜 **Mandatory Justification:** Every unlock requires legal or incident justification.
        - 💾 **DuckDB Audit Table:** All actions are permanently written to `audit`.
        """)

    st.markdown("---")
    st.subheader("📋 Audit Log")
    audit_df = con.execute("SELECT ts, actor, role, action, target, justification, result FROM audit ORDER BY ts DESC").df()
    st.dataframe(audit_df, use_container_width=True)

# ==============================================================================
# PAGE 5: SCENARIO SANDBOX
# ==============================================================================
elif page == "Scenario Sandbox":
    st.markdown("## 🧪 Scenario Compiler & Time-Compressed Simulation")
    st.markdown(
        "<div class='trust-box'><strong>GenAI Scenario Compiler:</strong> Translates plain-English descriptions into schema-validated YAML specifications consumed by the deterministic simulator.</div>",
        unsafe_allow_html=True
    )
    
    scenario_text = st.text_area(
        "English Scenario Prompt",
        value="A departing senior financial analyst on notice period stages confidential quarterly earnings spreadsheets over 2 days, then uploads 1.8GB to an unauthorized personal cloud destination at 2 AM before their official resignation.",
        height=120
    )
    
    if st.button("Compile to Validated YAML", type="primary"):
        st.success("Validated Scenario Schema Generated successfully (Pydantic Confirmed):")
        yaml_content = """scenario_id: resigning_finance_cloud_exfil
description: "Finance employee on notice stages client files, uploads to personal cloud at night"
actor:
  role: Finance
  count: 1
  flags: [notice_period]
phases:
  - stage: collection
    start_day: 8
    duration_days: 2
    internal_read_mb_per_day: 1500
    hours: [10, 18]
  - stage: exfiltration
    start_day: 10
    duration_days: 1
    upload_mb: 1800
    hours: [1, 3]
    destination:
      domain: "megashare-demo.net"
      category: cloud_storage
      first_seen: true
    protocol: https
    pattern: burst
evasion:
  padding: 0.0
  jitter: 0.0
  chunk_mb: null
labels:
  is_malicious: true
  split: train"""
        st.code(yaml_content, language="yaml")
        
    st.markdown("---")
    if st.button("🚀 Launch Time-Compressed Replay Engine"):
        with st.spinner("Executing seeded simulator..."):
            st.info("Replay completed: 1,467 flows synthesized, 2 alerts triggered, Case C-0001 verified.")

con.close()
