import os
import sys
import subprocess
from pathlib import Path
from pipeline.db import get_connection, init_db
from sim.engine import generate_golden_seed
from genai.dest_classifier import classify_destination

def main():
    print("=" * 70)
    print("  🛡️  INSIDERLENS: ENCRYPTED BEHAVIORAL SOC PLATFORM")
    print("  Push 1 Gate: Foundations, Contracts & Golden Seed Demo")
    print("=" * 70)

    db_path = Path("data/golden_seed.duckdb")
    if not db_path.exists():
        print("[*] Generating 5-user, 14-day Golden Seed DuckDB database...")
        generate_golden_seed(str(db_path))
    else:
        print(f"[✓] Golden Seed Database verified: {db_path} ({db_path.stat().st_size} bytes)")

    # Test LLM wrapper with on-prem / cached destination classifier
    print("[*] Verifying LLM Client wrapper & disk cache on sample destination...")
    test_dom = "megashare-demo.net"
    res = classify_destination(test_dom)
    print(f"[✓] Classification verified: {test_dom} -> {res.category.value} (conf: {res.confidence:.2f})")

    # Verify Database Tables
    con = get_connection(read_only=True)
    flows_cnt = con.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
    alerts_cnt = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    cases_cnt = con.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
    con.close()
    
    print(f"[✓] Ingested Telemetry: {flows_cnt} encrypted flows | {alerts_cnt} sensor alerts | {cases_cnt} correlated cases")
    print("-" * 70)
    print("🚀 Launching Streamlit SOC Dashboard at http://localhost:8501 ...")
    print("   Press Ctrl+C to terminate.")
    print("=" * 70)

    # Launch Streamlit
    subprocess.run([sys.executable, "-m", "streamlit", "run", "ui/app.py"])

if __name__ == "__main__":
    main()
