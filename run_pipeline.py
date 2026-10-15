"""
InsiderLens - Main Orchestrator
Runs the complete pipeline: data loading → feature engineering → detection → risk scoring → GenAI
Saves all results for the dashboard to consume.
"""
import sys
import os
import json
import pickle
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

import pandas as pd
import numpy as np

from insiderlens.pipeline import DataPipeline
from insiderlens.detectors import DetectionEngine
from insiderlens.risk_engine import RiskEngine
from insiderlens.genai_layer import GenAILayer
from insiderlens.config import DATA_DIR, MODELS_DIR, REPORTS_DIR


def run_pipeline():
    """Execute the complete InsiderLens detection pipeline."""
    print("=" * 70)
    print("  InsiderLens - Insider Threat Detection Platform")
    print("  Detecting data leaks in encrypted traffic without decrypting it")
    print("=" * 70)

    # ── Step 1: Data Loading ───────────────────────────────────────────
    print("\n[1/6] Loading and enriching data...")
    pipeline = DataPipeline(str(DATA_DIR))
    raw_data = pipeline.load_all_data()

    print(f"  Loaded {len(raw_data['flows'])} flow records")
    print(f"  Loaded {len(raw_data['users'])} users")
    print(f"  Date range: {raw_data['metadata']['date_range']}")
    print(f"  Scenarios: {list(raw_data['scenarios']['scenario_label'])}")

    # ── Step 2: Feature Engineering ────────────────────────────────────
    print("\n[2/6] Engineering features...")
    enriched_flows = pipeline.enrich_flows(raw_data["flows"])
    print(f"  Enriched flows with {len(enriched_flows.columns)} features")

    # Build user-level daily features
    user_daily = pipeline.build_user_features(enriched_flows, raw_data["users"])
    print(f"  Built {len(user_daily)} user-daily feature records")

    # Add baseline Z-scores and peer comparisons
    user_daily = pipeline.add_baseline_features(user_daily)
    print(f"  Added baseline Z-scores and peer comparisons")

    # ── Step 3: Detection ──────────────────────────────────────────────
    print("\n[3/6] Running detection engine (6 detectors)...")
    engine = DetectionEngine()
    engine.train(enriched_flows, user_daily)
    detector_results = engine.run_all(enriched_flows, user_daily)

    # ── Step 4: Risk Scoring & Correlation ─────────────────────────────
    print("\n[4/6] Computing risk scores and correlating cases...")
    risk_engine = RiskEngine()
    alerts = risk_engine.process_detector_results(detector_results, raw_data["users"])
    print(f"  Generated {len(alerts)} alerts")
    print(f"  Created {len(risk_engine.cases)} cases")

    risk_summary = risk_engine.get_risk_summary()
    cases_summary = risk_engine.get_cases_summary()

    print("\n  Risk Summary:")
    print("  " + "-" * 60)
    for _, row in risk_summary.iterrows():
        severity_marker = {"critical": "[!!!]", "high": "[!! ]", "medium": "[ ! ]", "low": "[ . ]", "info": "[   ]"}.get(row["severity"], "[   ]")
        print(f"  {severity_marker} {row['user_id']}: Risk={row['risk_score']:.1f} "
              f"({row['severity'].upper()}) | {row['alert_count']} alerts")

    # ── Step 5: GenAI Explanations ─────────────────────────────────────
    print("\n[5/6] Generating AI-powered explanations...")
    genai = GenAILayer()

    # Generate explanations for top-risk cases
    explanations = {}
    reports = {}

    for _, case_row in cases_summary.head(5).iterrows():
        case_id = case_row["case_id"]
        user_id = case_row["user_id"]
        case = risk_engine.cases[case_id]

        # Get explanation for the most significant alert in this case
        if case.alerts:
            top_alert = max(case.alerts, key=lambda a: a.score)
            alert_data = {
                "alert_id": top_alert.alert_id,
                "user_id": top_alert.user_id,
                "detector": top_alert.detector,
                "score": top_alert.score,
                "evidence_tags": top_alert.evidence_tags,
                "details": top_alert.shap_top_features,
                "kill_chain_stage": top_alert.kill_chain_stage,
                "timestamp": top_alert.timestamp,
            }
            explanation = genai.explain_alert(alert_data)
            explanations[case_id] = explanation

        # Generate timeline
        timeline = risk_engine.get_user_timeline(user_id)

        # Generate incident report for high-risk cases
        if case_row["severity"] in ["high", "critical", "medium"]:
            report = genai.generate_incident_report(
                case_data=case_row.to_dict(),
                user_timeline=timeline,
            )
            reports[case_id] = report

            # Save report to file
            report_path = REPORTS_DIR / f"report_{case_id.replace('-', '_')}.md"
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(report)
            print(f"  Saved report: {report_path}")

    # ── Step 6: Save Results ───────────────────────────────────────────
    print("\n[6/6] Saving results...")

    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(exist_ok=True)

    # Save enriched flows
    enriched_flows.to_csv(results_dir / "enriched_flows.csv", index=False)

    # Save user daily features
    user_daily.to_csv(results_dir / "user_daily_features.csv", index=False)

    # Save risk summary
    risk_summary.to_csv(results_dir / "risk_summary.csv", index=False)

    # Save cases
    cases_summary.to_csv(results_dir / "cases_summary.csv", index=False)

    # Save alerts
    alerts_data = []
    for alert in risk_engine.alerts:
        alerts_data.append({
            "alert_id": alert.alert_id,
            "timestamp": alert.timestamp,
            "user_id": alert.user_id,
            "detector": alert.detector,
            "score": alert.score,
            "evidence_tags": json.dumps(alert.evidence_tags),
            "kill_chain_stage": alert.kill_chain_stage,
            "case_id": alert.case_id,
            "status": alert.status,
        })
    pd.DataFrame(alerts_data).to_csv(results_dir / "alerts.csv", index=False)

    # Save explanations
    with open(results_dir / "explanations.json", "w") as f:
        json.dump(explanations, f, indent=2, default=str)

    # Save user timelines
    timelines = {}
    for user_id in risk_summary["user_id"]:
        timelines[user_id] = risk_engine.get_user_timeline(user_id)
    with open(results_dir / "timelines.json", "w") as f:
        json.dump(timelines, f, indent=2, default=str)

    # Save the risk engine state
    with open(results_dir / "risk_engine_state.pkl", "wb") as f:
        pickle.dump({
            "user_risks": risk_engine.user_risks,
            "cases": {k: {
                "case_id": v.case_id,
                "user_id": v.user_id,
                "first_seen": v.first_seen,
                "last_seen": v.last_seen,
                "risk_score": v.risk_score,
                "severity": v.severity,
                "stages": v.stages,
                "alert_count": len(v.alerts),
                "status": v.status,
            } for k, v in risk_engine.cases.items()},
        }, f)

    # Save SHAP values for the flow classifier
    try:
        shap_values, feature_names = engine.flow_classifier.get_shap_values(
            enriched_flows.head(200)
        )
        if shap_values is not None:
            np.save(results_dir / "shap_values.npy", shap_values)
            with open(results_dir / "shap_feature_names.json", "w") as f:
                json.dump(feature_names, f)
            print("  Saved SHAP explainability data")
    except Exception as e:
        print(f"  SHAP computation skipped: {e}")

    # Save XGBoost model
    try:
        engine.flow_classifier.model.save_model(str(MODELS_DIR / "flow_classifier.json"))
        print("  Saved XGBoost model")
    except Exception as e:
        print(f"  Model save skipped: {e}")

    print("\n" + "=" * 70)
    print("  Pipeline complete!")
    print(f"  Results saved to: {results_dir}")
    print(f"  Reports saved to: {REPORTS_DIR}")
    print(f"\n  To launch the dashboard, run:")
    print(f"    streamlit run dashboard.py")
    print("=" * 70)

    return {
        "enriched_flows": enriched_flows,
        "user_daily": user_daily,
        "risk_summary": risk_summary,
        "cases_summary": cases_summary,
        "alerts": alerts_data,
        "explanations": explanations,
        "timelines": timelines,
    }


if __name__ == "__main__":
    run_pipeline()
