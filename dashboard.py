"""
InsiderLens - Interactive Dashboard
Streamlit-based dashboard for insider threat detection monitoring.
"""
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import os
from pathlib import Path
from datetime import datetime

# ── Page Config ────────────────────────────────────────────────────────
st.set_page_config(
    page_title="InsiderLens - Insider Threat Detection",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ─────────────────────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');

    /* Main theme */
    .stApp {
        font-family: 'Inter', sans-serif;
    }

    /* Header styling */
    .main-header {
        background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
        padding: 1.5rem 2rem;
        border-radius: 16px;
        margin-bottom: 1.5rem;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        border: 1px solid rgba(255, 255, 255, 0.08);
    }

    .main-header h1 {
        color: #fff;
        font-size: 2rem;
        font-weight: 800;
        margin: 0;
        letter-spacing: -0.5px;
    }

    .main-header p {
        color: rgba(255, 255, 255, 0.7);
        font-size: 0.95rem;
        margin: 0.3rem 0 0 0;
    }

    /* Metric cards */
    .metric-card {
        background: linear-gradient(145deg, #1a1a2e 0%, #16213e 100%);
        border: 1px solid rgba(255, 255, 255, 0.06);
        border-radius: 14px;
        padding: 1.2rem 1.5rem;
        text-align: center;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
        transition: transform 0.2s, box-shadow 0.2s;
    }

    .metric-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 30px rgba(0, 0, 0, 0.35);
    }

    .metric-value {
        font-size: 2.2rem;
        font-weight: 800;
        margin: 0.3rem 0;
        background: linear-gradient(90deg, #00d2ff, #3a7bd5);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }

    .metric-label {
        font-size: 0.8rem;
        color: rgba(255, 255, 255, 0.5);
        text-transform: uppercase;
        letter-spacing: 1px;
        font-weight: 600;
    }

    /* Severity badges */
    .severity-critical { color: #ff4444; font-weight: 700; }
    .severity-high { color: #ff8c00; font-weight: 700; }
    .severity-medium { color: #ffd700; font-weight: 700; }
    .severity-low { color: #00c851; font-weight: 700; }

    /* Alert card */
    .alert-card {
        background: rgba(255, 255, 255, 0.03);
        border-left: 4px solid;
        border-radius: 8px;
        padding: 1rem 1.2rem;
        margin: 0.5rem 0;
        transition: background 0.2s;
    }

    .alert-card:hover {
        background: rgba(255, 255, 255, 0.06);
    }

    .alert-critical { border-color: #ff4444; }
    .alert-high { border-color: #ff8c00; }
    .alert-medium { border-color: #ffd700; }
    .alert-low { border-color: #00c851; }

    /* Section headers */
    .section-header {
        font-size: 1.1rem;
        font-weight: 700;
        color: #e0e0e0;
        margin: 1.5rem 0 0.8rem;
        padding-bottom: 0.4rem;
        border-bottom: 2px solid rgba(0, 210, 255, 0.3);
    }

    /* Kill chain progress */
    .killchain-stage {
        display: inline-block;
        padding: 0.3rem 0.8rem;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
        margin: 0.2rem;
    }

    .stage-active { background: rgba(255, 68, 68, 0.2); color: #ff6b6b; border: 1px solid rgba(255, 68, 68, 0.4); }
    .stage-inactive { background: rgba(255, 255, 255, 0.05); color: rgba(255, 255, 255, 0.3); border: 1px solid rgba(255, 255, 255, 0.1); }

    /* Copilot chat */
    .copilot-response {
        background: rgba(0, 210, 255, 0.05);
        border: 1px solid rgba(0, 210, 255, 0.2);
        border-radius: 12px;
        padding: 1.2rem;
        margin: 0.5rem 0;
        font-size: 0.9rem;
        line-height: 1.6;
    }

    /* Privacy badge */
    .privacy-badge {
        background: rgba(0, 200, 81, 0.1);
        border: 1px solid rgba(0, 200, 81, 0.3);
        border-radius: 20px;
        padding: 0.3rem 1rem;
        font-size: 0.75rem;
        color: #00c851;
        font-weight: 600;
        display: inline-block;
    }

    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0f0c29 0%, #1a1a2e 100%);
    }

    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}

    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 0.5rem;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px;
        padding: 0.5rem 1rem;
    }

    /* Dataframe styling */
    .stDataFrame {
        border-radius: 10px;
        overflow: hidden;
    }
</style>
""", unsafe_allow_html=True)


# ── Data Loading ───────────────────────────────────────────────────────
@st.cache_data
def load_results():
    """Load all pipeline results."""
    results_dir = Path(__file__).parent / "results"
    data = {}

    try:
        data["risk_summary"] = pd.read_csv(results_dir / "risk_summary.csv")
        data["cases_summary"] = pd.read_csv(results_dir / "cases_summary.csv")
        data["alerts"] = pd.read_csv(results_dir / "alerts.csv")
        data["enriched_flows"] = pd.read_csv(results_dir / "enriched_flows.csv")
        data["user_daily"] = pd.read_csv(results_dir / "user_daily_features.csv")

        with open(results_dir / "explanations.json") as f:
            data["explanations"] = json.load(f)
        with open(results_dir / "timelines.json") as f:
            data["timelines"] = json.load(f)

        # Load SHAP if available
        shap_path = results_dir / "shap_values.npy"
        if shap_path.exists():
            data["shap_values"] = np.load(shap_path)
            with open(results_dir / "shap_feature_names.json") as f:
                data["shap_features"] = json.load(f)

        data["loaded"] = True
    except FileNotFoundError as e:
        st.error(f"Results not found. Run `python run_pipeline.py` first!\n\nMissing: {e}")
        data["loaded"] = False

    return data


# Load data
data = load_results()

if not data.get("loaded", False):
    st.stop()


# ── Sidebar ────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="text-align: center; padding: 1rem 0;">
        <h2 style="color: #00d2ff; margin: 0; font-weight: 800;">🔍 InsiderLens</h2>
        <p style="color: rgba(255,255,255,0.5); font-size: 0.8rem; margin: 0.3rem 0 0;">
            Encrypted Traffic Threat Detection
        </p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    page = st.radio(
        "Navigation",
        ["🏠 Overview", "⚠️ Alerts & Cases", "👤 User Analysis",
         "🤖 AI Copilot", "📊 Analytics", "🔒 Privacy & Audit"],
        label_visibility="collapsed"
    )

    st.markdown("---")

    # Privacy badge
    st.markdown("""
    <div class="privacy-badge" style="margin: 0.5rem 0;">
        🔒 Privacy Mode Active
    </div>
    """, unsafe_allow_html=True)
    st.caption("No decrypted content • Pseudonymized IDs • Audit logged")

    st.markdown("---")
    st.caption(f"Last updated: {datetime.now().strftime('%H:%M:%S')}")
    st.caption(f"Flows analyzed: {len(data['enriched_flows']):,}")
    st.caption(f"Users monitored: {len(data['risk_summary'])}")


# ── Helper Functions ───────────────────────────────────────────────────
def severity_color(severity):
    return {"critical": "#ff4444", "high": "#ff8c00", "medium": "#ffd700", "low": "#00c851", "info": "#888"}.get(severity, "#888")

def severity_emoji(severity):
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}.get(severity, "⚪")


# ══════════════════════════════════════════════════════════════════════
# PAGE: OVERVIEW
# ══════════════════════════════════════════════════════════════════════
if page == "🏠 Overview":
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🔍 InsiderLens Dashboard</h1>
        <p>Detecting insider data leaks in encrypted traffic — without decrypting it</p>
    </div>
    """, unsafe_allow_html=True)

    # Top metrics
    col1, col2, col3, col4, col5 = st.columns(5)

    risk_df = data["risk_summary"]
    alerts_df = data["alerts"]
    cases_df = data["cases_summary"]

    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Total Alerts</div>
            <div class="metric-value">{len(alerts_df)}</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        critical_count = len(risk_df[risk_df["severity"] == "critical"])
        high_count = len(risk_df[risk_df["severity"] == "high"])
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Critical / High Users</div>
            <div class="metric-value" style="background: linear-gradient(90deg, #ff4444, #ff8c00); -webkit-background-clip: text;">
                {critical_count + high_count}
            </div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Open Cases</div>
            <div class="metric-value">{len(cases_df)}</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Users Monitored</div>
            <div class="metric-value">{len(risk_df)}</div>
        </div>
        """, unsafe_allow_html=True)

    with col5:
        avg_risk = risk_df["risk_score"].mean()
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Avg Risk Score</div>
            <div class="metric-value">{avg_risk:.1f}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Two column layout
    col_left, col_right = st.columns([3, 2])

    with col_left:
        st.markdown('<div class="section-header">📊 Risk Score Heatmap by User</div>', unsafe_allow_html=True)

        fig = go.Figure(go.Bar(
            x=risk_df["user_id"],
            y=risk_df["risk_score"],
            marker=dict(
                color=risk_df["risk_score"],
                colorscale=[[0, "#00c851"], [0.3, "#ffd700"], [0.6, "#ff8c00"], [1, "#ff4444"]],
                showscale=True,
                colorbar=dict(title="Risk", thickness=15),
            ),
            text=risk_df["severity"].str.upper(),
            textposition="outside",
            hovertemplate="<b>%{x}</b><br>Risk: %{y:.1f}<br>Severity: %{text}<extra></extra>",
        ))
        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=380,
            margin=dict(t=20, b=40, l=50, r=20),
            xaxis_title="User (Pseudonymized)",
            yaxis_title="Risk Score",
            font=dict(family="Inter"),
        )
        fig.add_hline(y=65, line_dash="dash", line_color="#ff4444",
                     annotation_text="High Risk Threshold", annotation_position="top right")
        fig.add_hline(y=40, line_dash="dot", line_color="#ffd700",
                     annotation_text="Medium", annotation_position="bottom right")
        st.plotly_chart(fig, use_container_width=True)

    with col_right:
        st.markdown('<div class="section-header">⚠️ Top Risk Users</div>', unsafe_allow_html=True)
        for _, row in risk_df.head(5).iterrows():
            emoji = severity_emoji(row["severity"])
            color = severity_color(row["severity"])
            st.markdown(f"""
            <div class="alert-card alert-{row['severity']}">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span style="font-weight: 700; color: #fff;">{emoji} {row['user_id']}</span>
                        <span style="color: {color}; font-weight: 600; margin-left: 0.5rem;">{row['severity'].upper()}</span>
                    </div>
                    <div style="font-size: 1.5rem; font-weight: 800; color: {color};">{row['risk_score']:.0f}</div>
                </div>
                <div style="color: rgba(255,255,255,0.5); font-size: 0.8rem; margin-top: 0.3rem;">
                    {row['alert_count']} alerts • {row['case_count']} case(s)
                </div>
            </div>
            """, unsafe_allow_html=True)

    # Bottom charts
    col_b1, col_b2 = st.columns(2)

    with col_b1:
        st.markdown('<div class="section-header">📈 Alerts by Detector</div>', unsafe_allow_html=True)
        detector_counts = alerts_df["detector"].value_counts()
        fig = px.pie(
            values=detector_counts.values,
            names=detector_counts.index,
            color_discrete_sequence=px.colors.sequential.Plasma_r,
            hole=0.45,
        )
        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=350,
            margin=dict(t=20, b=20),
            font=dict(family="Inter"),
            legend=dict(orientation="h", yanchor="bottom", y=-0.2),
        )
        fig.update_traces(textposition='inside', textinfo='percent+label',
                         textfont_size=11)
        st.plotly_chart(fig, use_container_width=True)

    with col_b2:
        st.markdown('<div class="section-header">📅 Daily Outbound Volume by User</div>', unsafe_allow_html=True)
        daily = data["user_daily"]
        fig = px.line(
            daily, x="date", y="total_bytes_out",
            color="user_id",
            color_discrete_sequence=px.colors.qualitative.Set2,
        )
        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=350,
            margin=dict(t=20, b=20),
            xaxis_title="Date",
            yaxis_title="Bytes Out",
            font=dict(family="Inter"),
            legend=dict(orientation="h", yanchor="bottom", y=-0.35, font=dict(size=9)),
        )
        st.plotly_chart(fig, use_container_width=True)


# ══════════════════════════════════════════════════════════════════════
# PAGE: ALERTS & CASES
# ══════════════════════════════════════════════════════════════════════
elif page == "⚠️ Alerts & Cases":
    st.markdown("""
    <div class="main-header">
        <h1>⚠️ Alerts & Cases</h1>
        <p>Kill-chain correlated alerts grouped into investigation cases</p>
    </div>
    """, unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["📋 Cases", "🔔 All Alerts"])

    with tab1:
        cases_df = data["cases_summary"]
        if len(cases_df) > 0:
            for _, case in cases_df.iterrows():
                severity = case["severity"]
                emoji = severity_emoji(severity)
                color = severity_color(severity)

                with st.expander(f"{emoji} {case['case_id']} — {case['user_id']} — Risk: {case['risk_score']:.0f} ({severity.upper()})"):
                    col1, col2, col3 = st.columns(3)
                    col1.metric("Risk Score", f"{case['risk_score']:.1f}")
                    col2.metric("Alerts", case["alert_count"])
                    col3.metric("Severity", severity.upper())

                    # Kill chain visualization
                    stages = eval(str(case["stages"])) if isinstance(case["stages"], str) else case.get("stages", [])
                    st.markdown("**Kill Chain Progress:**")
                    kill_chain_html = ""
                    for stage_num, stage_name in [(1, "Recon"), (2, "Staging"), (3, "Exfil"), (4, "Cover-up")]:
                        cls = "stage-active" if stage_num in stages else "stage-inactive"
                        kill_chain_html += f'<span class="killchain-stage {cls}">{stage_num}. {stage_name}</span> '
                    st.markdown(kill_chain_html, unsafe_allow_html=True)

                    # Show explanation if available
                    case_id = case["case_id"]
                    if case_id in data.get("explanations", {}):
                        exp = data["explanations"][case_id]
                        st.markdown("---")
                        st.markdown("**🤖 AI-Generated Explanation:**")
                        st.markdown(f"""
                        <div class="copilot-response">
                            <p><strong>Summary:</strong> {exp.get('summary', 'N/A')}</p>
                            <p><strong>Why Flagged:</strong></p>
                            <ul>{''.join(f'<li>{r}</li>' for r in exp.get('why_flagged', []))}</ul>
                            <p><strong>Confidence:</strong> {exp.get('confidence', 'N/A')}</p>
                            <p><strong>Recommended Actions:</strong></p>
                            <ul>{''.join(f'<li>{a}</li>' for a in exp.get('recommended_actions', []))}</ul>
                        </div>
                        """, unsafe_allow_html=True)

                    # Show timeline
                    user_id = case["user_id"]
                    if user_id in data.get("timelines", {}):
                        timeline = data["timelines"][user_id]
                        if timeline:
                            st.markdown("**📅 Alert Timeline:**")
                            tl_df = pd.DataFrame(timeline)
                            st.dataframe(tl_df, use_container_width=True, hide_index=True)

                    # Report download
                    report_path = Path(__file__).parent / "reports" / f"report_{case_id.replace('-', '_')}.md"
                    if report_path.exists():
                        with open(report_path) as f:
                            report_content = f.read()
                        st.download_button(
                            "📥 Download Incident Report",
                            report_content,
                            file_name=f"{case_id}_report.md",
                            mime="text/markdown",
                        )
        else:
            st.info("No cases found.")

    with tab2:
        alerts_df = data["alerts"].copy()

        # Filters
        col1, col2, col3 = st.columns(3)
        with col1:
            det_filter = st.multiselect("Detector", alerts_df["detector"].unique(), default=alerts_df["detector"].unique())
        with col2:
            user_filter = st.multiselect("User", alerts_df["user_id"].unique(), default=alerts_df["user_id"].unique())
        with col3:
            score_min = st.slider("Min Score", 0.0, 1.0, 0.0)

        filtered = alerts_df[
            (alerts_df["detector"].isin(det_filter)) &
            (alerts_df["user_id"].isin(user_filter)) &
            (alerts_df["score"] >= score_min)
        ]

        st.dataframe(
            filtered.sort_values("score", ascending=False),
            use_container_width=True,
            hide_index=True,
            column_config={
                "score": st.column_config.ProgressColumn(
                    "Score", min_value=0, max_value=1, format="%.2f",
                ),
            },
        )


# ══════════════════════════════════════════════════════════════════════
# PAGE: USER ANALYSIS
# ══════════════════════════════════════════════════════════════════════
elif page == "👤 User Analysis":
    st.markdown("""
    <div class="main-header">
        <h1>👤 User Analysis</h1>
        <p>Deep-dive into individual user behavior and baselines</p>
    </div>
    """, unsafe_allow_html=True)

    # User selector
    risk_df = data["risk_summary"]
    user_options = risk_df.sort_values("risk_score", ascending=False)["user_id"].tolist()
    selected_user = st.selectbox(
        "Select User",
        user_options,
        format_func=lambda u: f"{severity_emoji(risk_df[risk_df['user_id']==u]['severity'].values[0])} {u} (Risk: {risk_df[risk_df['user_id']==u]['risk_score'].values[0]:.0f})"
    )

    if selected_user:
        user_risk = risk_df[risk_df["user_id"] == selected_user].iloc[0]
        daily = data["user_daily"]
        user_daily = daily[daily["user_id"] == selected_user].sort_values("date")

        # User overview
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Risk Score", f"{user_risk['risk_score']:.1f}", delta=user_risk["severity"].upper())
        col2.metric("Total Alerts", user_risk["alert_count"])
        col3.metric("Cases", user_risk["case_count"])
        if "role" in user_daily.columns and len(user_daily) > 0:
            col4.metric("Role", user_daily["role"].iloc[0])

        st.markdown("---")

        # Charts
        col_l, col_r = st.columns(2)

        with col_l:
            st.markdown("**📈 Daily Outbound Volume**")
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=user_daily["date"], y=user_daily["total_bytes_out"],
                mode="lines+markers",
                name="Bytes Out",
                line=dict(color="#00d2ff", width=2),
                fill="tozeroy",
                fillcolor="rgba(0, 210, 255, 0.1)",
            ))

            # Add peer average if available
            peer_dept = user_daily["department"].iloc[0] if "department" in user_daily.columns else None
            if peer_dept:
                peer_avg = daily[daily["department"] == peer_dept].groupby("date")["total_bytes_out"].mean()
                fig.add_trace(go.Scatter(
                    x=peer_avg.index, y=peer_avg.values,
                    mode="lines",
                    name=f"Peer Avg ({peer_dept})",
                    line=dict(color="#ff8c00", width=1, dash="dash"),
                ))

            fig.update_layout(
                template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                height=320, margin=dict(t=10, b=30),
                yaxis_title="Bytes", font=dict(family="Inter", size=11),
                legend=dict(orientation="h", yanchor="bottom", y=1.02),
            )
            st.plotly_chart(fig, use_container_width=True)

        with col_r:
            st.markdown("**📊 Activity Distribution by Hour**")
            user_flows = data["enriched_flows"][data["enriched_flows"]["user_id"] == selected_user]
            if "hour" in user_flows.columns:
                hour_dist = user_flows.groupby("hour").size().reindex(range(24), fill_value=0)
                fig = go.Figure(go.Bar(
                    x=hour_dist.index, y=hour_dist.values,
                    marker=dict(
                        color=["#ff4444" if (h >= 20 or h < 7) else "#00d2ff" for h in range(24)],
                    ),
                ))
                fig.update_layout(
                    template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    height=320, margin=dict(t=10, b=30),
                    xaxis_title="Hour of Day", yaxis_title="Flow Count",
                    font=dict(family="Inter", size=11),
                )
                # Highlight after-hours
                fig.add_vrect(x0=19.5, x1=23.5, fillcolor="rgba(255,68,68,0.08)", layer="below")
                fig.add_vrect(x0=-0.5, x1=6.5, fillcolor="rgba(255,68,68,0.08)", layer="below")
                st.plotly_chart(fig, use_container_width=True)

        # Z-score trends
        st.markdown("**📉 Baseline Deviation (Z-Score vs Self History)**")
        z_cols = [c for c in user_daily.columns if c.endswith("_z_self")]
        if z_cols:
            fig = go.Figure()
            colors = px.colors.qualitative.Set2
            for i, col in enumerate(z_cols[:4]):
                name = col.replace("_z_self", "").replace("_", " ").title()
                fig.add_trace(go.Scatter(
                    x=user_daily["date"], y=user_daily[col],
                    mode="lines+markers",
                    name=name,
                    line=dict(color=colors[i % len(colors)], width=2),
                ))
            fig.add_hline(y=2, line_dash="dash", line_color="#ff8c00", annotation_text="Warning (2σ)")
            fig.add_hline(y=3, line_dash="dash", line_color="#ff4444", annotation_text="Critical (3σ)")
            fig.add_hline(y=0, line_dash="dot", line_color="rgba(255,255,255,0.2)")
            fig.update_layout(
                template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                height=300, margin=dict(t=10, b=30),
                yaxis_title="Z-Score",
                font=dict(family="Inter", size=11),
                legend=dict(orientation="h", yanchor="bottom", y=-0.3),
            )
            st.plotly_chart(fig, use_container_width=True)

        # User timeline
        st.markdown("**📅 Alert Timeline**")
        if selected_user in data.get("timelines", {}):
            timeline = data["timelines"][selected_user]
            if timeline:
                st.dataframe(pd.DataFrame(timeline), use_container_width=True, hide_index=True)
            else:
                st.info("No alerts for this user.")


# ══════════════════════════════════════════════════════════════════════
# PAGE: AI COPILOT
# ══════════════════════════════════════════════════════════════════════
elif page == "🤖 AI Copilot":
    st.markdown("""
    <div class="main-header">
        <h1>🤖 AI Analyst Copilot</h1>
        <p>Natural-language threat hunting — ask questions about the data</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div style="background: rgba(0,210,255,0.05); border: 1px solid rgba(0,210,255,0.2); border-radius: 12px; padding: 1rem; margin-bottom: 1rem;">
        <strong>💡 Example questions:</strong>
        <ul style="margin: 0.5rem 0;">
            <li>Who is the highest risk user?</li>
            <li>How many alerts were generated today?</li>
            <li>Show me all open cases</li>
            <li>Which users uploaded more than 500MB?</li>
            <li>What happened with USER-003?</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

    # Initialize the GenAI layer
    from insiderlens.genai_layer import GenAILayer
    genai = GenAILayer()

    # Chat interface
    if "messages" not in st.session_state:
        st.session_state.messages = []

    # Display chat history
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # Chat input
    if prompt := st.chat_input("Ask about the security data..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        # Build context for the copilot
        context = {
            "risk_summary": data["risk_summary"].to_dict(orient="records"),
            "cases": data["cases_summary"].to_dict(orient="records") if "cases_summary" in data else [],
            "total_alerts": len(data["alerts"]),
            "total_users": len(data["risk_summary"]),
            "detectors_used": data["alerts"]["detector"].unique().tolist(),
        }

        # Check for user-specific questions
        for user_id in data["risk_summary"]["user_id"].values:
            if user_id.lower() in prompt.lower():
                user_data = data["risk_summary"][data["risk_summary"]["user_id"] == user_id].to_dict(orient="records")
                context["queried_user"] = user_data
                if user_id in data.get("timelines", {}):
                    context["user_timeline"] = data["timelines"][user_id]
                user_daily = data["user_daily"][data["user_daily"]["user_id"] == user_id]
                if len(user_daily) > 0:
                    context["user_daily_stats"] = {
                        "avg_bytes_out": float(user_daily["total_bytes_out"].mean()),
                        "max_bytes_out": float(user_daily["total_bytes_out"].max()),
                        "avg_flows": float(user_daily["total_flows"].mean()),
                        "avg_after_hours_ratio": float(user_daily.get("after_hours_ratio", pd.Series([0])).mean()),
                    }

        # Get response
        with st.chat_message("assistant"):
            response = genai.generate_copilot_response(prompt, context)
            st.markdown(f"""
            <div class="copilot-response">
                {response}
            </div>
            """, unsafe_allow_html=True)
            st.session_state.messages.append({"role": "assistant", "content": response})


# ══════════════════════════════════════════════════════════════════════
# PAGE: ANALYTICS
# ══════════════════════════════════════════════════════════════════════
elif page == "📊 Analytics":
    st.markdown("""
    <div class="main-header">
        <h1>📊 Detection Analytics</h1>
        <p>Deep analysis of detection patterns and model performance</p>
    </div>
    """, unsafe_allow_html=True)

    tab1, tab2, tab3 = st.tabs(["🔍 Detection Analysis", "📈 Feature Importance", "🌐 Network Graph"])

    with tab1:
        alerts_df = data["alerts"]

        col1, col2 = st.columns(2)

        with col1:
            # Alerts over time
            if "timestamp" in alerts_df.columns:
                alerts_df["alert_date"] = pd.to_datetime(alerts_df["timestamp"], errors="coerce").dt.date
                daily_alerts = alerts_df.groupby(["alert_date", "detector"]).size().reset_index(name="count")
                fig = px.bar(
                    daily_alerts, x="alert_date", y="count", color="detector",
                    color_discrete_sequence=px.colors.qualitative.Set2,
                    title="Alerts per Day by Detector",
                )
                fig.update_layout(
                    template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    height=380, margin=dict(t=40, b=30), font=dict(family="Inter"),
                    legend=dict(orientation="h", yanchor="bottom", y=-0.25),
                )
                st.plotly_chart(fig, use_container_width=True)

        with col2:
            # Score distribution
            fig = px.histogram(
                alerts_df, x="score", nbins=30, color="detector",
                color_discrete_sequence=px.colors.qualitative.Set2,
                title="Alert Score Distribution",
            )
            fig.update_layout(
                template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                height=380, margin=dict(t=40, b=30), font=dict(family="Inter"),
                barmode="overlay",
                legend=dict(orientation="h", yanchor="bottom", y=-0.25),
            )
            fig.update_traces(opacity=0.7)
            st.plotly_chart(fig, use_container_width=True)

        # Department risk comparison
        st.markdown("**🏢 Risk by Department**")
        daily = data["user_daily"]
        dept_stats = daily.groupby("department").agg(
            avg_bytes_out=("total_bytes_out", "mean"),
            max_bytes_out=("total_bytes_out", "max"),
            avg_after_hours=("after_hours_ratio", "mean"),
        ).reset_index()

        fig = px.bar(
            dept_stats, x="department", y=["avg_bytes_out", "max_bytes_out"],
            barmode="group",
            color_discrete_sequence=["#00d2ff", "#ff8c00"],
            title="Average vs Max Daily Outbound by Department",
        )
        fig.update_layout(
            template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            height=350, margin=dict(t=40, b=30), font=dict(family="Inter"),
        )
        st.plotly_chart(fig, use_container_width=True)

    with tab2:
        st.markdown("**🎯 SHAP Feature Importance (XGBoost Flow Classifier)**")

        if "shap_values" in data and "shap_features" in data:
            shap_vals = data["shap_values"]
            features = data["shap_features"]

            mean_abs_shap = np.abs(shap_vals).mean(axis=0)
            importance_df = pd.DataFrame({
                "Feature": features,
                "Mean |SHAP|": mean_abs_shap,
            }).sort_values("Mean |SHAP|", ascending=True)

            fig = px.bar(
                importance_df, x="Mean |SHAP|", y="Feature",
                orientation="h",
                color="Mean |SHAP|",
                color_continuous_scale="Plasma",
            )
            fig.update_layout(
                template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                height=450, margin=dict(t=10, b=30, l=150),
                font=dict(family="Inter"),
                showlegend=False,
            )
            st.plotly_chart(fig, use_container_width=True)

            st.caption("SHAP values show each feature's contribution to the model's prediction. "
                      "Higher values mean the feature is more important for detecting exfiltration-like flows.")
        else:
            st.info("SHAP values not available. Run the pipeline to generate them.")

    with tab3:
        st.markdown("**🌐 User-Destination Network**")
        flows = data["enriched_flows"]

        # Build user-destination graph
        user_dest = flows.groupby(["user_id", "dst_ip"]).agg(
            total_bytes=("bytes_out", "sum"),
            flow_count=("flow_id", "count"),
        ).reset_index()

        # Top connections
        top_connections = user_dest.nlargest(50, "total_bytes")

        fig = go.Figure()

        # Add edges
        for _, row in top_connections.iterrows():
            fig.add_trace(go.Scatter(
                x=[0, 1], y=[hash(row["user_id"]) % 100, hash(row["dst_ip"]) % 100],
                mode="lines",
                line=dict(width=max(0.5, row["total_bytes"] / top_connections["total_bytes"].max() * 3),
                         color="rgba(0, 210, 255, 0.3)"),
                hoverinfo="skip",
                showlegend=False,
            ))

        # Add user nodes
        users = top_connections["user_id"].unique()
        fig.add_trace(go.Scatter(
            x=[0] * len(users),
            y=[hash(u) % 100 for u in users],
            mode="markers+text",
            marker=dict(size=12, color="#00d2ff"),
            text=list(users),
            textposition="middle left",
            name="Users",
        ))

        # Add destination nodes
        dsts = top_connections["dst_ip"].unique()
        fig.add_trace(go.Scatter(
            x=[1] * len(dsts),
            y=[hash(d) % 100 for d in dsts],
            mode="markers",
            marker=dict(size=8, color="#ff8c00"),
            text=list(dsts),
            name="Destinations",
            hoverinfo="text",
        ))

        fig.update_layout(
            template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            height=500, margin=dict(t=10, b=30),
            font=dict(family="Inter"),
            xaxis=dict(visible=False), yaxis=dict(visible=False),
        )
        st.plotly_chart(fig, use_container_width=True)


# ══════════════════════════════════════════════════════════════════════
# PAGE: PRIVACY & AUDIT
# ══════════════════════════════════════════════════════════════════════
elif page == "🔒 Privacy & Audit":
    st.markdown("""
    <div class="main-header">
        <h1>🔒 Privacy & Audit Controls</h1>
        <p>Pseudonymization, access control, and compliance audit trail</p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown('<div class="section-header">🔐 Privacy-by-Design Controls</div>', unsafe_allow_html=True)

        controls = [
            ("🚫 No Decryption", "Only network metadata is collected. No TLS interception or payload inspection.", True),
            ("🔒 Pseudonymization", "All user IDs are pseudonymized. Real identities stored separately, encrypted.", True),
            ("🚪 Gated De-anonymization", "Revealing real identity requires risk ≥ HIGH and authorized role approval.", True),
            ("👤 Role-Based Access", "Analyst, Lead, Auditor, and Admin roles with different permission levels.", True),
            ("📝 Complete Audit Trail", "Every query, reveal, and export is logged immutably.", True),
            ("🤝 Human-in-the-Loop", "System recommends actions; humans make all decisions.", True),
            ("📊 Bias Monitoring", "Alert rates monitored by role/department to prevent unfair targeting.", True),
            ("🗑️ Data Minimization", "No file names, URLs, or content stored. Configurable retention (90 days).", True),
        ]

        for name, desc, active in controls:
            status = "✅ Active" if active else "❌ Inactive"
            st.markdown(f"""
            <div style="background: rgba(0,200,81,0.05); border: 1px solid rgba(0,200,81,0.15); border-radius: 8px; padding: 0.8rem; margin: 0.4rem 0;">
                <div style="display: flex; justify-content: space-between;">
                    <strong>{name}</strong>
                    <span style="color: #00c851; font-size: 0.8rem;">{status}</span>
                </div>
                <p style="color: rgba(255,255,255,0.5); font-size: 0.8rem; margin: 0.3rem 0 0;">{desc}</p>
            </div>
            """, unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="section-header">📋 Simulated Audit Log</div>', unsafe_allow_html=True)

        audit_entries = [
            {"ts": "2026-10-14 14:32:15", "actor": "Analyst-A", "action": "Query", "target": "alerts table", "result": "Success"},
            {"ts": "2026-10-14 14:35:22", "actor": "Analyst-A", "action": "View Case", "target": "CASE-0001", "result": "Success"},
            {"ts": "2026-10-14 14:40:10", "actor": "Analyst-A", "action": "Reveal Request", "target": "USER-003", "result": "Pending Approval"},
            {"ts": "2026-10-14 14:42:05", "actor": "Lead-B", "action": "Approve Reveal", "target": "USER-003", "result": "Approved"},
            {"ts": "2026-10-14 14:43:30", "actor": "Analyst-A", "action": "Export Report", "target": "CASE-0001", "result": "Success"},
            {"ts": "2026-10-14 15:10:00", "actor": "Analyst-A", "action": "Label Alert", "target": "ALT-00005", "result": "True Positive"},
            {"ts": "2026-10-14 15:15:00", "actor": "System", "action": "Pipeline Run", "target": "All flows", "result": "Complete"},
        ]

        st.dataframe(
            pd.DataFrame(audit_entries),
            use_container_width=True,
            hide_index=True,
        )

        st.markdown('<div class="section-header">🔓 Identity Reveal Request</div>', unsafe_allow_html=True)

        # Reveal request form
        with st.form("reveal_form"):
            reveal_user = st.selectbox("Pseudonymous User ID", data["risk_summary"]["user_id"].tolist())
            justification = st.text_area("Justification", placeholder="Explain why de-anonymization is needed...")
            submitted = st.form_submit_button("Request Reveal")

            if submitted:
                user_risk = data["risk_summary"][data["risk_summary"]["user_id"] == reveal_user]["risk_score"].values[0]
                user_sev = data["risk_summary"][data["risk_summary"]["user_id"] == reveal_user]["severity"].values[0]

                if user_sev in ["high", "critical"] and justification:
                    st.success(f"✅ Reveal request submitted for {reveal_user}. Pending Lead approval.")
                elif not justification:
                    st.error("❌ Justification is required for all reveal requests.")
                else:
                    st.warning(f"⚠️ User risk level ({user_sev}) is below the HIGH threshold required for reveal. "
                             "Continue monitoring or provide additional evidence.")
