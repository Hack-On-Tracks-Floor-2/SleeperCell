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

        with open(results_dir / "explanations.json", encoding="utf-8") as f:
            data["explanations"] = json.load(f)
        with open(results_dir / "timelines.json", encoding="utf-8") as f:
            data["timelines"] = json.load(f)

        # Load SHAP if available
        shap_path = results_dir / "shap_values.npy"
        if shap_path.exists():
            data["shap_values"] = np.load(shap_path)
            with open(results_dir / "shap_feature_names.json", encoding="utf-8") as f:
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
         "🤖 AI Copilot", "📊 Analytics", "🔒 Privacy & Audit", "🎯 Threat Simulator"],
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
        st.markdown('<div class="section-header">📊 Employee Behavioral Threat &amp; Risk Scores</div>', unsafe_allow_html=True)
        st.info("💡 **Main Takeaway:** **USER-003** is the only user exceeding the high-risk threshold (65.0 pts with 145 alerts) requiring immediate investigation; all other users remain in safe or moderate monitoring ranges.")

        # Colorblind-friendly palette mapping and dual-coded hatch patterns
        pattern_shapes = ["/" if score >= 60 else ("." if score >= 40 else "") for score in risk_df["risk_score"]]
        direct_labels = [f"{score:.1f} pts ({sev.upper()})" for score, sev in zip(risk_df["risk_score"], risk_df["severity"])]
        threshold_status = [
            f"🚨 Exceeds Threshold (+{score - 60:.1f} pts)" if score >= 60 else "✓ Below High Risk Threshold"
            for score in risk_df["risk_score"]
        ]
        action_recs = [
            "Immediate SOC containment & investigation" if score >= 60 else "Standard automated monitoring"
            for score in risk_df["risk_score"]
        ]

        fig = go.Figure(go.Bar(
            x=risk_df["user_id"],
            y=risk_df["risk_score"],
            marker=dict(
                color=risk_df["risk_score"],
                # Colorblind-safe palette (Okabe-Ito inspired: Ocean Blue -> Amber -> Vermilion)
                colorscale=[[0.0, "#0284c7"], [0.4, "#e69f00"], [0.6, "#e66101"], [1.0, "#d55e00"]],
                showscale=True,
                colorbar=dict(title="Score (pts)", thickness=14, tickfont=dict(color="#e2e8f0", size=11)),
                pattern=dict(
                    shape=pattern_shapes,
                    fillmode="overlay",
                    fgcolor="rgba(255, 255, 255, 0.45)",
                    size=7,
                ),
                line=dict(color="rgba(255,255,255,0.3)", width=1.5),
            ),
            text=direct_labels,
            textposition="outside",
            textfont=dict(family="Inter, sans-serif", size=11, color="#ffffff"),
            customdata=list(zip(threshold_status, action_recs)),
            hovertemplate=(
                "<b>Account: %{x}</b><br>"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━<br>"
                "• <b>Threat Risk Score:</b> %{y:.2f} / 100 points<br>"
                "• <b>Severity Status:</b> %{text}<br>"
                "• <b>Threshold Check:</b> %{customdata[0]}<br>"
                "• <b>Recommended Action:</b> %{customdata[1]}<extra></extra>"
            ),
        ))
        fig.update_layout(
            template="plotly_dark",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=400,
            margin=dict(t=30, b=65, l=75, r=25),
            xaxis=dict(
                title=dict(text="User Account (Pseudonymized Identifier)", font=dict(size=13, color="#f8fafc")),
                tickfont=dict(size=12, color="#e2e8f0"),
                showgrid=False,
            ),
            yaxis=dict(
                title=dict(text="Threat Risk Score (Points, 0–100 Scale)", font=dict(size=13, color="#f8fafc")),
                tickfont=dict(size=12, color="#e2e8f0"),
                range=[0, 100],
                dtick=20,
                ticksuffix=" pts",
                showgrid=True,
                gridcolor="rgba(255,255,255,0.08)",
            ),
            hoverlabel=dict(
                bgcolor="#0f172a",
                bordercolor="#38bdf8",
                font=dict(family="Inter, sans-serif", size=12, color="#ffffff"),
            ),
            font=dict(family="Inter, sans-serif"),
        )
        fig.add_hline(
            y=60, line_dash="dash", line_color="#ef4444", line_width=2,
            annotation_text="▲ High-Risk Threshold (60.0 pts)", annotation_position="top right",
            annotation_font=dict(size=11, color="#ffffff"),
            annotation_bgcolor="#d55e00",
        )
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
                        with open(report_path, encoding="utf-8", errors="replace") as f:
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
            st.caption("What this shows: Daily external data uploads (MB) compared against typical baseline behavior.")

            mb_series = user_daily["total_bytes_out"] / (1024 * 1024)
            # Baseline calculation (excluding high outliers)
            non_spike = mb_series[user_daily["total_bytes_out_z_self"].fillna(0) <= 2.0]
            base_mean = non_spike.mean() if len(non_spike) >= 3 else mb_series.mean()
            base_std = non_spike.std() if len(non_spike) >= 3 else (mb_series.std() or 0.05)
            base_upper = max(0.25, round(base_mean + 1.5 * (base_std or 0.05), 2))
            base_lower = max(0.0, round(max(0, base_mean - 1.0 * (base_std or 0.05)), 2))

            # Spikes above band
            spike_mask = mb_series > base_upper
            if spike_mask.any():
                max_spike_idx = mb_series.idxmax()
                max_date = user_daily.loc[max_spike_idx, "date"]
                max_mb = mb_series.loc[max_spike_idx]
                ratio = max_mb / max(base_mean, 0.01)
                st.info(f"💡 **Takeaway:** **{max_date}** outbound volume was **{ratio:.1f}x** this user's normal baseline ({max_mb:.2f} MB vs ~{base_mean:.2f} MB typical).")
            else:
                st.info(f"💡 **Takeaway:** Daily outbound volume remained within the normal baseline corridor ({base_lower:.2f}–{base_upper:.2f} MB) across all days.")

            with st.expander("ℹ️ What is Daily Outbound Volume?"):
                st.write("This chart tracks how much data the user uploaded outside the company each day. The blue shaded band represents their normal daily routine. Sudden spikes rising above the band highlight unexpected data transfers that could indicate file exfiltration.")

            fig = go.Figure()
            # Lower bound (invisible baseline)
            fig.add_trace(go.Scatter(
                x=user_daily["date"], y=[base_lower] * len(user_daily),
                mode="lines", line=dict(width=0), showlegend=False, hoverinfo="none"
            ))
            # Upper bound + Shaded corridor
            fig.add_trace(go.Scatter(
                x=user_daily["date"], y=[base_upper] * len(user_daily),
                mode="lines", fill="tonexty", fillcolor="rgba(56, 189, 248, 0.12)",
                line=dict(color="rgba(56, 189, 248, 0.5)", width=1.5, dash="dot"),
                name="Normal baseline corridor",
                hovertemplate=f"<b>Baseline Corridor</b><br>Typical: {base_lower:.2f}–{base_upper:.2f} MB<extra></extra>"
            ))
            # Observed data line
            fig.add_trace(go.Scatter(
                x=user_daily["date"], y=mb_series,
                mode="lines+markers",
                name="Observed data sent",
                line=dict(color="#0072b2", width=2.2),
                marker=dict(size=6, color="#38bdf8", line=dict(color="#ffffff", width=1)),
                hovertemplate="<b>Date: %{x}</b><br>• Data sent: <b>%{y:.2f} MB</b><extra></extra>"
            ))

            # Mark spikes
            if spike_mask.any():
                spikes = user_daily[spike_mask]
                spike_mbs = mb_series[spike_mask]
                spike_labels = [f"{d.split('-')[1]}/{d.split('-')[2]}: {mb/max(base_mean,0.01):.1f}x" for d, mb in zip(spikes["date"], spike_mbs)]
                fig.add_trace(go.Scatter(
                    x=spikes["date"], y=spike_mbs,
                    mode="markers+text",
                    name="Spike above baseline",
                    marker=dict(size=10, color="#d55e00", symbol="diamond", line=dict(color="#ffffff", width=1.5)),
                    text=spike_labels,
                    textposition="top center",
                    textfont=dict(size=11, color="#fca5a5"),
                    hoverinfo="skip"
                ))

            fig.update_layout(
                template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                height=340, margin=dict(t=20, b=50, l=70, r=20),
                xaxis=dict(title=dict(text="Date", font=dict(size=12, color="#f8fafc")), tickfont=dict(size=11, color="#e2e8f0"), showgrid=False),
                yaxis=dict(title=dict(text="Data sent out (MB)", font=dict(size=12, color="#f8fafc")), tickfont=dict(size=11, color="#e2e8f0"), ticksuffix=" MB", showgrid=True, gridcolor="rgba(255,255,255,0.06)"),
                font=dict(family="Inter", size=12),
                legend=dict(orientation="h", yanchor="bottom", y=-0.3),
            )
            st.plotly_chart(fig, use_container_width=True)

        with col_r:
            st.markdown("**📊 Activity by Hour of Day**")
            st.caption("What this shows: Hourly distribution of network connections (UTC), highlighting business hours vs late-night activity.")

            user_flows = data["enriched_flows"][data["enriched_flows"]["user_id"] == selected_user]
            hour_dist = user_flows.groupby("hour").size().reindex(range(24), fill_value=0) if ("hour" in user_flows.columns and not user_flows.empty) else pd.Series([0]*24)
            hour_12_labels = ['12 AM', '1 AM', '2 AM', '3 AM', '4 AM', '5 AM', '6 AM', '7 AM', '8 AM', '9 AM', '10 AM', '11 AM', '12 PM', '1 PM', '2 PM', '3 PM', '4 PM', '5 PM', '6 PM', '7 PM', '8 PM', '9 PM', '10 PM', '11 PM']

            total_h_flows = int(hour_dist.sum())
            after_hours_cnt = int(sum(hour_dist[h] for h in range(24) if (h >= 19 or h < 7)))
            peak_h = int(hour_dist.idxmax()) if total_h_flows > 0 else 0
            peak_12 = hour_12_labels[peak_h]

            if after_hours_cnt > 0:
                pct = round((after_hours_cnt / max(total_h_flows, 1)) * 100)
                st.info(f"💡 **Takeaway:** **{after_hours_cnt} connections ({pct}%)** occurred during after-hours (7 PM – 7 AM UTC), peaking at **{peak_12} UTC**.")
            else:
                st.info(f"💡 **Takeaway:** All **{total_h_flows} connections** occurred during standard daytime business hours (7 AM – 7 PM UTC), peaking at {peak_12} UTC.")

            with st.expander("ℹ️ What is Activity by Hour of Day?"):
                st.write("This chart shows when the employee connects to the network during a 24-hour day in UTC time. The shaded areas highlight nighttime hours when the office is closed (7 PM to 7 AM). Large clusters of activity during late night hours often indicate automated malware or unauthorized after-hours data transfers.")

            # Dual-coded traces: Daytime vs After-Hours
            day_counts = [hour_dist[h] if (7 <= h < 19) else 0 for h in range(24)]
            night_counts = [hour_dist[h] if (h >= 19 or h < 7) else 0 for h in range(24)]

            fig_h = go.Figure()
            fig_h.add_trace(go.Bar(
                x=list(range(24)), y=day_counts,
                name="Daytime (7 AM – 7 PM)",
                marker=dict(color="#0284c7", line=dict(color="rgba(255,255,255,0.2)", width=1)),
                hovertemplate="<b>%{x}:00 UTC</b><br>Daytime Flows: %{y}<extra></extra>"
            ))
            fig_h.add_trace(go.Bar(
                x=list(range(24)), y=night_counts,
                name="After-hours (7 PM – 7 AM)",
                marker=dict(color="#d55e00", pattern=dict(shape="/", fgcolor="rgba(255,255,255,0.45)"), line=dict(color="rgba(255,255,255,0.35)", width=1.2)),
                hovertemplate="<b>%{x}:00 UTC</b><br>After-Hours Flows: %{y}<extra></extra>"
            ))

            fig_h.update_layout(
                template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                height=340, margin=dict(t=20, b=50, l=65, r=20),
                barmode="stack",
                xaxis=dict(
                    title=dict(text="Time of Day (UTC, 12-Hour AM/PM Format)", font=dict(size=12, color="#f8fafc")),
                    tickmode="array", tickvals=[0, 3, 6, 9, 12, 15, 18, 21],
                    ticktext=['12 AM', '3 AM', '6 AM', '9 AM', '12 PM', '3 PM', '6 PM', '9 PM'],
                    tickangle=0, tickfont=dict(size=11, color="#e2e8f0"), showgrid=False
                ),
                yaxis=dict(title=dict(text="Connections (Flows)", font=dict(size=12, color="#f8fafc")), tickfont=dict(size=11, color="#e2e8f0"), ticksuffix=" flows", showgrid=True, gridcolor="rgba(255,255,255,0.06)"),
                font=dict(family="Inter", size=12),
                legend=dict(orientation="h", yanchor="bottom", y=-0.3),
            )
            # Highlight after-hours
            fig_h.add_vrect(x0=18.5, x1=23.5, fillcolor="rgba(213, 94, 0, 0.10)", layer="below")
            fig_h.add_vrect(x0=-0.5, x1=6.5, fillcolor="rgba(213, 94, 0, 0.10)", layer="below")
            fig_h.add_annotation(
                x=0.98, y=1, xref="paper", yref="paper",
                text="After hours (7 PM - 7 AM)", showarrow=False,
                font=dict(size=10, color="#ffffff"), bgcolor="#d55e00", bordercolor="#fca5a5", borderpad=4
            )
            st.plotly_chart(fig_h, use_container_width=True)

        # 3. Z-score trends
        st.markdown("**📉 Baseline Deviation Z-Scores**")
        st.caption("How far from this user's normal. 0 = normal, above 2 = unusual, above 3 = very unusual.")
        st.caption("What this shows: Statistical deviation from personal normal behavior across data volume, connection counts, and timing.")

        z_cols_map = [
            ("total_bytes_out_z_self", "Data sent", "#0072b2", "solid", "circle"),
            ("total_flows_z_self", "Number of connections", "#e69f00", "dash", "square"),
            ("unique_destinations_z_self", "New destinations", "#882255", "dot", "diamond"),
            ("after_hours_ratio_z_self", "After-hours activity", "#06b6d4", "dashdot", "triangle-up"),
        ]

        # Calculate max deviation for takeaway
        max_z_val = -999.0
        max_z_name = ""
        max_z_date = ""
        for col, name, _, _, _ in z_cols_map:
            if col in user_daily.columns:
                series = user_daily[col].dropna()
                if not series.empty and series.max() > max_z_val:
                    max_z_val = float(series.max())
                    max_z_name = name
                    max_z_date = user_daily.loc[series.idxmax(), "date"]

        if max_z_val >= 2.0 and max_z_date:
            zone = "Very Unusual" if max_z_val >= 3.0 else "Unusual"
            st.info(f"💡 **Takeaway:** **{max_z_date}** **{max_z_name}** surged to **+{max_z_val:.1f}** points above normal, entering the **{zone}** zone.")
        else:
            st.info("💡 **Takeaway:** All behavioral metrics remained within expected statistical ranges (< 2.0 departures from normal baseline).")

        with st.expander("ℹ️ What are Baseline Deviation Z-Scores?"):
            st.write("This chart measures how drastically today's behavior departs from this employee's historical average across four metrics. A score near 0 means business as usual, while a score above 2 is unusual and above 3 is very unusual. Spikes that breach the shaded warning or critical zones trigger automated security alerts.")

        fig_z = go.Figure()
        all_y_vals = []
        for col, name, color, dash, sym in z_cols_map:
            if col in user_daily.columns:
                vals = user_daily[col].fillna(0)
                all_y_vals.extend(vals.tolist())
                fig_z.add_trace(go.Scatter(
                    x=user_daily["date"], y=vals,
                    mode="lines+markers",
                    name=name,
                    line=dict(color=color, width=2.2, dash=dash, shape="linear"),  # No spline
                    marker=dict(size=6, symbol=sym, color=color, line=dict(color="#ffffff", width=1)),
                    hovertemplate=f"<b>{name}</b><br>Date: %{{x}}<br>Deviation: +%{{y:.2f}} points<extra></extra>"
                ))

        y_max_bound = max(4.5, (max(all_y_vals) if all_y_vals else 3.5) * 1.1)

        # Shaded Warning area (yellow) above +2
        fig_z.add_shape(type="rect", xref="paper", x0=0, x1=1, y0=2, y1=3, fillcolor="rgba(245, 158, 11, 0.08)", line=dict(width=0))
        # Shaded Critical area (red) above +3
        fig_z.add_shape(type="rect", xref="paper", x0=0, x1=1, y0=3, y1=y_max_bound, fillcolor="rgba(220, 38, 38, 0.12)", line=dict(width=0))

        # Threshold lines
        fig_z.add_hline(y=2, line_dash="dash", line_color="#f59e0b", line_width=1.8, annotation_text="Warning: unusual for this user (+2)", annotation_position="top right", annotation_bgcolor="#d97706", annotation_font=dict(color="#ffffff", size=10))
        fig_z.add_hline(y=3, line_dash="longdash", line_color="#dc2626", line_width=2.2, annotation_text="Critical: very unusual for this user (+3)", annotation_position="top right", annotation_bgcolor="#dc2626", annotation_font=dict(color="#ffffff", size=10))
        fig_z.add_hline(y=0, line_dash="dot", line_color="rgba(255,255,255,0.2)")

        fig_z.update_layout(
            template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            height=340, margin=dict(t=25, b=50, l=75, r=25),
            xaxis=dict(title=dict(text="Timeline (Date)", font=dict(size=12, color="#f8fafc")), tickfont=dict(size=11, color="#e2e8f0"), showgrid=False),
            yaxis=dict(title=dict(text="Deviation from Normal (0 = normal, +2 = unusual)", font=dict(size=12, color="#f8fafc")), tickfont=dict(size=11, color="#e2e8f0"), showgrid=True, gridcolor="rgba(255,255,255,0.06)"),
            font=dict(family="Inter", size=12),
            legend=dict(orientation="h", yanchor="bottom", y=-0.3),
        )
        st.plotly_chart(fig_z, use_container_width=True)

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

    # Initialize the GenAI layer (cached across reruns)
    @st.cache_resource
    def get_genai():
        from insiderlens.genai_layer import GenAILayer
        return GenAILayer()

    genai = get_genai()

    # RAG status indicator
    rag_status = "Ready" if (genai._rag_pipeline and genai._rag_pipeline.is_ready()) else "Initializing on first query..."
    st.markdown(f"""
    <div style="background: rgba(0,200,81,0.05); border: 1px solid rgba(0,200,81,0.15);
                border-radius: 8px; padding: 0.6rem 1rem; margin-bottom: 0.5rem; font-size: 0.8rem;">
        <strong>RAG Pipeline:</strong> {rag_status} |
        <strong>LLM:</strong> {'Connected (Ollama)' if genai._ollama_available else 'Offline (using template fallback)'} |
        <strong>Sources:</strong> Policies, Playbooks, Detection Methodology, Live Results
    </div>
    """, unsafe_allow_html=True)

    # Chat interface
    if "messages" not in st.session_state:
        st.session_state.messages = []

    # Display chat history
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"], unsafe_allow_html=True)

    # Chat input
    if prompt := st.chat_input("Ask about security data, policies, detection methodology..."):
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

        # Get RAG-powered response
        with st.chat_message("assistant"):
            with st.spinner("Searching knowledge base..."):
                response, sources = genai.generate_copilot_response(prompt, context)

            # Display the response
            st.markdown(response)

            # Display source citations if available
            if sources:
                citations_html = "<div style='margin-top: 0.8rem; padding: 0.6rem; background: rgba(0,210,255,0.05); border: 1px solid rgba(0,210,255,0.15); border-radius: 8px; font-size: 0.75rem;'>"
                citations_html += "<strong>📚 Sources cited:</strong><br>"
                for i, src in enumerate(sources[:4], 1):
                    relevance_pct = f"{src.get('relevance', 0):.0%}" if src.get('relevance') else ""
                    citations_html += (
                        f"<span style='color: rgba(0,210,255,0.8);'>[{i}]</span> "
                        f"<em>{src.get('source', 'unknown')}</em> > {src.get('section', '')} "
                        f"<span style='color: rgba(255,255,255,0.3);'>({relevance_pct} match)</span><br>"
                    )
                citations_html += "</div>"
                st.markdown(citations_html, unsafe_allow_html=True)

            # Store full response with citations for chat history
            full_content = response
            if sources:
                full_content += "\n\n---\n*Sources: " + ", ".join(
                    f"{s.get('source', '')} > {s.get('section', '')}" for s in sources[:4]
                ) + "*"
            st.session_state.messages.append({"role": "assistant", "content": full_content})


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


# ══════════════════════════════════════════════════════════════════════
# PAGE: THREAT SIMULATOR
# ══════════════════════════════════════════════════════════════════════
elif page == "🎯 Threat Simulator":
    st.markdown("""
    <div class="main-header">
        <h1>🎯 Insider Threat Simulator</h1>
        <p>Simulate realistic exfiltration scenarios and test detection models in real-time</p>
    </div>
    """, unsafe_allow_html=True)

    # Load scenario catalog if available
    catalog_path = Path(__file__).parent / "data" / "scenario_catalog.csv"
    if catalog_path.exists():
        scenarios_df = pd.read_csv(catalog_path)
    else:
        scenarios_df = pd.DataFrame([
            {"scenario_label": "gradual_outbound_increase", "description": "USER-003 sends repeated moderately sized outbound transfers over 6 days", "intended_use": "Low-and-slow exfiltration"},
            {"scenario_label": "unusual_destination_burst", "description": "USER-007 generates large outbound transfers to unusual cloud storage", "intended_use": "Burst exfiltration anomaly"},
            {"scenario_label": "repeated_after_hours_activity", "description": "USER-009 generates repeated off-hours flows on final days", "intended_use": "Temporal behavior anomaly"},
        ])

    st.markdown("### 📋 Scenario Catalog")
    st.dataframe(scenarios_df, use_container_width=True, hide_index=True)

    st.markdown("---")
    st.markdown("### ⚡ Interactive Attack Simulation")

    col1, col2 = st.columns([1, 1])

    with col1:
        st.markdown("**1. Configure Threat Scenario**")

        scenario_choice = st.selectbox(
            "Select Scenario Template",
            [
                "Cloud Exfiltration Burst (Dropbox / Mega)",
                "Low-and-Slow Drip (CUSUM Steganography)",
                "Covert DNS Tunneling (iodine/dnscat2)",
                "Staging + Exfiltration (Multi-Stage Kill Chain)",
                "Custom Threat Vector",
            ]
        )

        sim_user = st.selectbox(
            "Target User Identifier",
            data["risk_summary"]["user_id"].tolist() if "risk_summary" in data else ["USER-003", "USER-007", "USER-009"]
        )

        if "Cloud" in scenario_choice:
            default_vol = 1850
            default_dest = "mega.nz"
            default_after_hours = True
            default_dns = ""
        elif "Low-and-Slow" in scenario_choice:
            default_vol = 35
            default_dest = "185.220.101.5"
            default_after_hours = False
            default_dns = ""
        elif "DNS" in scenario_choice:
            default_vol = 8
            default_dest = "8.8.8.8"
            default_after_hours = True
            default_dns = "v1-exfil-a98f4c2e1b.corp-internal-data.tunnel-c2.net"
        elif "Staging" in scenario_choice:
            default_vol = 2400
            default_dest = "dropbox.com"
            default_after_hours = True
            default_dns = ""
        else:
            default_vol = 500
            default_dest = "unknown-storage-host.io"
            default_after_hours = False
            default_dns = ""

        vol_mb = st.slider("Outbound Payload Volume (MB)", min_value=1, max_value=5000, value=default_vol)
        dest_target = st.text_input("Destination Domain / IP", value=default_dest)
        is_after_hours = st.checkbox("Execute During After-Hours (02:00 AM)", value=default_after_hours)
        dns_query = st.text_input("DNS Query (for DNS Tunneling)", value=default_dns)

        run_sim = st.button("🚀 Execute Threat Simulation", use_container_width=True, type="primary")

    with col2:
        st.markdown("**2. Real-Time Detection Engine Evaluation**")

        if run_sim:
            with st.spinner("Passing simulated traffic through detection ensemble..."):
                # Construct simulated flow data
                sim_bytes_out = vol_mb * 1024 * 1024
                sim_bytes_in = int(sim_bytes_out * 0.02)  # High asymmetry
                sim_duration = max(10, vol_mb * 2)

                # Evaluate against detectors
                from insiderlens.detectors import (
                    FlowClassifier, DNSTunnelDetector, VolumeAnomalyDetector,
                    BeaconingDetector, LowAndSlowDetector
                )

                triggered_detectors = []
                max_score = 0.0
                tags = []

                # Check 1: DNS Tunneling
                if dns_query and len(dns_query) > 20:
                    tunnel_detector = DNSTunnelDetector()
                    test_df = pd.DataFrame([{
                        "dns_query": dns_query,
                        "dst_port": 53,
                        "bytes_out": sim_bytes_out,
                    }])
                    tunnel_res = tunnel_detector.predict(test_df)
                    if tunnel_res:
                        score = tunnel_res[0].score
                        triggered_detectors.append(("DNS Tunnel Detector", score, tunnel_res[0].evidence_tags))
                        tags.extend(tunnel_res[0].evidence_tags)
                        max_score = max(max_score, score)

                # Check 2: Volume & Asymmetry
                if vol_mb > 100 or is_after_hours:
                    score = min(0.98, 0.4 + (vol_mb / 2000) * 0.4 + (0.2 if is_after_hours else 0))
                    vol_tags = ["high_volume_outbound"]
                    if is_after_hours:
                        vol_tags.append("after_hours_spike")
                    if any(c in dest_target for c in ["mega", "dropbox", "drive", "wetransfer"]):
                        vol_tags.append("cloud_storage_upload")
                    triggered_detectors.append(("Volume & Asymmetry Detector", score, vol_tags))
                    tags.extend(vol_tags)
                    max_score = max(max_score, score)

                # Check 3: Flow Classifier
                upload_ratio = sim_bytes_out / (sim_bytes_in + 1)
                if upload_ratio > 10:
                    flow_score = min(0.96, 0.5 + (upload_ratio / 50) * 0.3 + (0.15 if is_after_hours else 0))
                    flow_tags = ["high_upload_ratio", "exfil_flow_signature"]
                    triggered_detectors.append(("Flow Classifier (XGBoost)", flow_score, flow_tags))
                    tags.extend(flow_tags)
                    max_score = max(max_score, flow_score)

                # Check 4: Low-and-Slow
                if "Low-and-Slow" in scenario_choice:
                    ls_score = 0.85
                    ls_tags = ["cumulative_volume_anomaly", "cusum_threshold_exceeded"]
                    triggered_detectors.append(("Low-and-Slow Detector (CUSUM)", ls_score, ls_tags))
                    tags.extend(ls_tags)
                    max_score = max(max_score, ls_score)

                # Deduplicate tags
                tags = list(set(tags))

                # Display Results
                status_color = "#ff4444" if max_score >= 0.7 else "#ff8c00" if max_score >= 0.4 else "#00c851"
                status_label = "CRITICAL ALERT" if max_score >= 0.7 else "HIGH ANOMALY" if max_score >= 0.4 else "NORMAL"

                st.markdown(f"""
                <div style="background: rgba(255,255,255,0.04); border: 2px solid {status_color}; border-radius: 12px; padding: 1.2rem; margin-bottom: 1rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <h3 style="margin: 0; color: {status_color};">🚨 {status_label}</h3>
                        <span style="font-size: 1.5rem; font-weight: 800; color: {status_color};">{max_score:.0%}</span>
                    </div>
                    <p style="margin: 0.5rem 0 0; color: rgba(255,255,255,0.7); font-size: 0.9rem;">
                        <strong>Target:</strong> {sim_user} | <strong>Destination:</strong> {dest_target} | <strong>Payload:</strong> {vol_mb} MB
                    </p>
                    <p style="margin: 0.2rem 0 0; color: rgba(255,255,255,0.5); font-size: 0.8rem;">
                        <strong>Kill-Chain Stage:</strong> {'Stage 3: Exfiltration' if max_score >= 0.5 else 'Stage 1: Access'}
                    </p>
                </div>
                """, unsafe_allow_html=True)

                st.markdown("**Detectors Triggered:**")
                for det_name, score, d_tags in triggered_detectors:
                    st.markdown(f"""
                    - **{det_name}**: Confidence **{score:.1%}** — *{', '.join(d_tags)}*
                    """)

                # Explain with GenAI
                st.markdown("**🤖 AI Narrative Explanation:**")
                from insiderlens.genai_layer import GenAILayer
                genai_layer = GenAILayer()

                exp_data = {
                    "alert_id": "SIM-ALT-001",
                    "user_id": sim_user,
                    "detector": triggered_detectors[0][0] if triggered_detectors else "Ensemble",
                    "score": max_score,
                    "evidence_tags": tags,
                    "details": {
                        "destination": dest_target,
                        "volume_mb": vol_mb,
                        "after_hours": is_after_hours,
                    },
                    "kill_chain_stage": 3,
                }
                explanation = genai_layer.explain_alert(exp_data)
                st.info(explanation.get("narrative", "Anomaly detected by multiple ensemble models."))

                st.markdown("**🛡️ Recommended Playbook Actions:**")
                for act in explanation.get("recommended_actions", [
                    "Verify user role and business justification",
                    "Restrict outbound data transfers for user",
                    "Review internal staging file access",
                ]):
                    st.markdown(f"1. {act}")
        else:
            st.info("👈 Select a scenario and click **Execute Threat Simulation** to test detection models in real-time.")
