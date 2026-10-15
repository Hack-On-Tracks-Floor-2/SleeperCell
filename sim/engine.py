import os
import json
import random
import csv
import math
from datetime import datetime, timedelta, timezone, date
from pathlib import Path
from typing import List, Dict, Tuple

import duckdb
from pipeline.db import init_db, get_db_path, get_connection
from pipeline.pseudonymize import get_pseudonymizer
from sim.personas import GOLDEN_SEED_PERSONAS, Persona

SIMULATION_DAYS = 14
BASE_DATE = date.today() - timedelta(days=SIMULATION_DAYS)

DOMAIN_METADATA = {
    "netsuite.com": {"category": "business_saas", "asn": "AS16509", "country": "US", "age": 8500},
    "bloomberg.com": {"category": "business_saas", "asn": "AS12345", "country": "US", "age": 10200},
    "microsoft365.com": {"category": "business_saas", "asn": "AS8075", "country": "US", "age": 6000},
    "sharepoint.internal.corp": {"category": "business_saas", "asn": "AS_INTERNAL", "country": "INTERNAL", "age": 1800},
    "workday.com": {"category": "business_saas", "asn": "AS36351", "country": "US", "age": 7200},
    "github.com": {"category": "dev_tool", "asn": "AS36459", "country": "US", "age": 6100},
    "registry.npmjs.org": {"category": "dev_tool", "asn": "AS13335", "country": "US", "age": 4800},
    "pypi.org": {"category": "dev_tool", "asn": "AS13335", "country": "US", "age": 5200},
    "aws.amazon.com": {"category": "cloud_storage", "asn": "AS16509", "country": "US", "age": 9000},
    "datadoghq.com": {"category": "business_saas", "asn": "AS16509", "country": "US", "age": 4500},
    "gitlab.internal.corp": {"category": "dev_tool", "asn": "AS_INTERNAL", "country": "INTERNAL", "age": 1800},
    "greenhouse.io": {"category": "business_saas", "asn": "AS13335", "country": "US", "age": 4300},
    "docu-sign.net": {"category": "business_saas", "asn": "AS13335", "country": "US", "age": 7500},
    "slack.com": {"category": "messaging", "asn": "AS16509", "country": "US", "age": 4900},
    "salesforce.com": {"category": "business_saas", "asn": "AS14340", "country": "US", "age": 9800},
    "zoom.us": {"category": "messaging", "asn": "AS20473", "country": "US", "age": 5100},
    "hubspot.com": {"category": "business_saas", "asn": "AS13335", "country": "US", "age": 6700},
    "linkedin.com": {"category": "business_saas", "asn": "AS14413", "country": "US", "age": 8200},
    "gong.io": {"category": "business_saas", "asn": "AS16509", "country": "US", "age": 3100},
    "grafana.net": {"category": "business_saas", "asn": "AS13335", "country": "US", "age": 3900},
    "pagerduty.com": {"category": "business_saas", "asn": "AS16509", "country": "US", "age": 5500},
    "cloudflare.com": {"category": "business_saas", "asn": "AS13335", "country": "US", "age": 6300},
    "vault.internal.corp": {"category": "dev_tool", "asn": "AS_INTERNAL", "country": "INTERNAL", "age": 1800},
    "megashare-demo.net": {"category": "cloud_storage", "asn": "AS49544", "country": "BG", "age": 14} # rare, malicious target
}

def generate_golden_seed(db_path: str = None) -> None:
    target_db = db_path or get_db_path()
    os.makedirs(os.path.dirname(os.path.abspath(target_db)), exist_ok=True)
    
    # Initialize Schema
    init_db(target_db)
    con = duckdb.connect(target_db)
    pseudonymizer = get_pseudonymizer()
    
    # Clean up tables
    tables = [
        "flows", "dns_events", "user_features_daily", "event_tokens",
        "dest_intel", "context", "alerts", "cases", "case_verdicts",
        "narratives", "audit", "llm_calls"
    ]
    for tbl in tables:
        con.execute(f"DELETE FROM {tbl}")
    
    random.seed(42)
    
    # 1. Map identities & generate users_directory.csv
    user_pids: Dict[str, str] = {}
    users_dir_rows = []
    for idx, p in enumerate(GOLDEN_SEED_PERSONAS):
        pid = pseudonymizer.get_or_create(p.name, seed=100 + idx)
        user_pids[p.name] = pid
        email = f"{p.name.lower().replace(' ', '.')}@example.com"
        users_dir_rows.append({
            "user_pid": pid,
            "fake_name": p.name,
            "role": p.role,
            "dept": p.department,
            "email": email,
            "flags": ",".join(p.flags)
        })
    
    users_csv_path = Path("data/synthetic/users_directory.csv")
    users_csv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(users_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["user_pid", "fake_name", "role", "dept", "email", "flags"])
        writer.writeheader()
        writer.writerows(users_dir_rows)
    
    # 2. Populate dest_intel
    for domain, meta in DOMAIN_METADATA.items():
        con.execute(
            """
            INSERT INTO dest_intel (domain, category, confidence, source, classified_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            [domain, meta["category"], 0.98 if meta["category"] != "unknown" else 0.5, "static", datetime.now(timezone.utc)]
        )
        
    # 3. Simulate 14 days of flows and daily features
    flows_rows = []
    dns_rows = []
    user_features_rows = []
    
    finance_persona = GOLDEN_SEED_PERSONAS[0]
    finance_pid = user_pids[finance_persona.name]
    
    flow_counter = 1
    
    for day_idx in range(SIMULATION_DAYS):
        current_date = BASE_DATE + timedelta(days=day_idx)
        is_weekend = current_date.weekday() >= 5
        
        for p in GOLDEN_SEED_PERSONAS:
            pid = user_pids[p.name]
            is_insider = (p.department == "Finance")
            
            # Baseline activity
            daily_mb = max(5.0, random.gauss(p.daily_mb_mean, p.daily_mb_std))
            if is_weekend:
                daily_mb *= 0.05
                
            internal_read_mb = daily_mb * 0.4
            upload_mb = daily_mb
            destinations = list(p.typical_destinations)
            off_hours_flows = 0
            total_flows_day = 0
            
            # Attack Scenario Phases:
            # Days 8-9: Collection / Staging (high internal reads)
            # Day 10: Exfiltration at 2 AM to megashare-demo.net (1.8 GB burst)
            is_attack_day = False
            attack_stage = None
            if is_insider:
                if day_idx in (8, 9):
                    internal_read_mb += 1500.0 # Staging internal financial records
                    attack_stage = "collection"
                elif day_idx == 10:
                    is_attack_day = True
                    upload_mb += 1800.0 # 1.8 GB exfiltration
                    destinations.append("megashare-demo.net")
                    attack_stage = "exfiltration"

            # Generate individual flows
            n_flows = 3 if is_weekend and not is_attack_day else random.randint(18, 35)
            if is_attack_day:
                n_flows += 25
                
            bytes_out_total = 0
            unique_dests_day = set()
            
            for f_idx in range(n_flows):
                flow_id = f"F-{flow_counter:06d}"
                flow_counter += 1
                
                # Determine time
                if is_attack_day and f_idx >= (n_flows - 15):
                    # Attack flows: 2:15 AM to 2:45 AM
                    hour = random.choice([1, 2])
                    minute = random.randint(0, 59)
                    second = random.randint(0, 59)
                    dst_domain = "megashare-demo.net"
                    flow_bytes_out = int((1800 * 1024 * 1024) / 15 + random.randint(1000, 50000))
                    flow_bytes_in = int(flow_bytes_out * 0.02)
                    is_malicious = True
                    off_hours_flows += 1
                else:
                    if random.random() < 0.05:
                        hour = random.choice([20, 21, 22, 23, 6, 7])
                        off_hours_flows += 1
                    else:
                        hour = random.randint(p.work_start_hour, p.work_end_hour - 1)
                    minute = random.randint(0, 59)
                    second = random.randint(0, 59)
                    dst_domain = random.choice(destinations)
                    flow_bytes_out = int((upload_mb * 1024 * 1024 / n_flows) * random.uniform(0.5, 1.5))
                    flow_bytes_in = int(flow_bytes_out * random.uniform(0.8, 3.0))
                    is_malicious = False
                    
                total_flows_day += 1
                bytes_out_total += flow_bytes_out
                unique_dests_day.add(dst_domain)
                
                dt_start = datetime.combine(current_date, datetime.min.time(), tzinfo=timezone.utc) + timedelta(hours=hour, minutes=minute, seconds=second)
                duration = random.uniform(1.2, 45.0)
                dt_end = dt_start + timedelta(seconds=duration)
                
                meta = DOMAIN_METADATA.get(dst_domain, {"category": "unknown", "asn": "AS_UNKNOWN", "country": "US", "age": 365})
                
                flows_rows.append((
                    flow_id,
                    dt_start,
                    dt_end,
                    pid,
                    f"198.51.100.{random.randint(10, 250)}",
                    443,
                    "tcp",
                    flow_bytes_out,
                    flow_bytes_in,
                    max(10, int(flow_bytes_out / 1300)),
                    max(10, int(flow_bytes_in / 1300)),
                    duration,
                    dst_domain,
                    "q120300_0000_0000",
                    "TLSv1.3",
                    False,
                    meta["asn"],
                    meta["country"],
                    meta["age"],
                    meta["category"],
                    "train",
                    is_malicious
                ))
                
                # DNS event
                dns_rows.append((
                    dt_start - timedelta(milliseconds=random.randint(20, 150)),
                    pid,
                    dst_domain,
                    "A",
                    random.randint(64, 256),
                    "NOERROR"
                ))
            
            # Daily aggregate features
            offhours_share = (off_hours_flows / total_flows_day) if total_flows_day > 0 else 0.0
            upload_ratio = (bytes_out_total / (bytes_out_total + 1024 * 1024 * 50))
            z_score = (upload_mb - p.daily_mb_mean) / (p.daily_mb_std + 1e-5)
            pct_peer = 0.5 if not is_attack_day else 0.999
            
            user_features_rows.append((
                pid,
                current_date,
                p.role,
                p.department,
                bytes_out_total,
                len(unique_dests_day),
                1 if "megashare-demo.net" in unique_dests_day else 0,
                round(upload_ratio, 4),
                round(offhours_share, 4),
                int(internal_read_mb * 1024 * 1024),
                round(z_score, 2),
                round(pct_peer, 3),
                int(bytes_out_total * 7),
                int(bytes_out_total * 14)
            ))
            
    # Insert flows
    con.executemany(
        """
        INSERT INTO flows VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        flows_rows
    )
    
    # Insert DNS
    con.executemany(
        """
        INSERT INTO dns_events VALUES (?, ?, ?, ?, ?, ?)
        """,
        dns_rows
    )
    
    # Insert Daily features
    con.executemany(
        """
        INSERT INTO user_features_daily VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        user_features_rows
    )
    
    # 4. Context Entry: HR Departure Notice for Elena Rostova (U-xxxx)
    attack_date = BASE_DATE + timedelta(days=10)
    con.execute(
        """
        INSERT INTO context (context_id, subject, type, start, "end", expected_destinations, expected_volume_mb, source_ticket_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            "CTX-HR-0042",
            finance_pid,
            "departure",
            datetime.combine(BASE_DATE + timedelta(days=5), datetime.min.time(), tzinfo=timezone.utc),
            datetime.combine(BASE_DATE + timedelta(days=20), datetime.min.time(), tzinfo=timezone.utc),
            "netsuite.com,microsoft365.com",
            100.0,
            "HR-TICKET-8891"
        ]
    )
    
    # 5. Insert Alerts for the Finance Insider
    alert_ts_1 = datetime.combine(BASE_DATE + timedelta(days=8), datetime.min.time(), tzinfo=timezone.utc) + timedelta(hours=14, minutes=20)
    alert_ts_2 = datetime.combine(BASE_DATE + timedelta(days=10), datetime.min.time(), tzinfo=timezone.utc) + timedelta(hours=2, minutes=25)
    
    con.execute(
        """
        INSERT INTO alerts (alert_id, ts, user_pid, detector, score, evidence_tags, top_features, stage, case_id)
        VALUES 
        (?, ?, ?, ?, ?, ?, ?, ?, ?),
        (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            # Alert 1: Collection / Staging
            "ALT-0101",
            alert_ts_1,
            finance_pid,
            "behaviour_lm",
            0.84,
            json.dumps(["internal_read_anomaly", "sensitive_sharepoint_access", "off_profile_staging"]),
            json.dumps({"internal_read_mb": 1500, "z_vs_self": 3.8, "dept_percentile": 0.98}),
            "collection",
            "C-0001",
            
            # Alert 2: Exfiltration Burst
            "ALT-0102",
            alert_ts_2,
            finance_pid,
            "flow_xgb",
            0.96,
            json.dumps(["upload_ratio_burst", "new_destination", "off_hours_2am", "rare_asn"]),
            json.dumps({"upload_mb": 1800, "destination": "megashare-demo.net", "hour": 2, "z_vs_self": 9.4}),
            "exfiltration",
            "C-0001"
        ]
    )
    
    # 6. Insert Case C-0001
    con.execute(
        """
        INSERT INTO cases (case_id, user_pid, first_seen, last_seen, risk_score, band, stages, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            "C-0001",
            finance_pid,
            alert_ts_1,
            alert_ts_2,
            88.5,
            "Critical",
            "collection,exfiltration",
            "OPEN"
        ]
    )
    
    # 7. Insert GenAI Verdict
    con.execute(
        """
        INSERT INTO case_verdicts (case_id, verdict, priority_delta, reasoning, evidence_ids, confidence, model_band, final_band)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            "C-0001",
            "escalate",
            1,
            "High confidence data exfiltration following internal document staging. Subject uploaded 1800MB to newly observed domain megashare-demo.net at 02:25 UTC. Behavioral context indicates active departure notice period (CTX-HR-0042) with no approved data transfer ticket.",
            json.dumps(["ALT-0101", "ALT-0102", "CTX-HR-0042"]),
            "high",
            "High",
            "Critical"
        ]
    )
    
    # 8. Insert Verified Narrative
    narrative_text = (
        "Subject U-4921 exhibited critical risk behavior starting on day 8 with 1500MB internal record staging "
        "from sharepoint.internal.corp (ALT-0101). On day 10 at 02:25 UTC, the subject initiated an encrypted 1800MB "
        "bulk upload to previously unseen external cloud host megashare-demo.net (ALT-0102). "
        "Context cross-referencing confirmed subject has an active departure notice (CTX-HR-0042) with an expected "
        "daily quota of 100MB. Evidence strictly confirms staged exfiltration outside sanctioned business hours."
    )
    con.execute(
        """
        INSERT INTO narratives (case_id, text, verified_pct, unverified_sentences)
        VALUES (?, ?, ?, ?)
        """,
        [
            "C-0001",
            narrative_text,
            100.0,
            json.dumps([])
        ]
    )
    
    # 9. Audit trail initialization
    con.execute(
        """
        INSERT INTO audit (ts, actor, role, action, target, justification, result)
        VALUES 
        (?, ?, ?, ?, ?, ?, ?),
        (?, ?, ?, ?, ?, ?, ?)
        """,
        [
            datetime.now(timezone.utc) - timedelta(hours=2),
            "system_init",
            "System",
            "database_seed",
            "golden_seed.duckdb",
            "Initial synthetic population generation for 5 users and 14 days",
            "SUCCESS",
            datetime.now(timezone.utc) - timedelta(minutes=45),
            "sec_analyst_01",
            "SOC_Analyst",
            "case_review",
            "C-0001",
            "Reviewing critical priority alert ALT-0102",
            "VIEWED"
        ]
    )
    
    # 10. Sample LLM call log
    con.execute(
        """
        INSERT INTO llm_calls (ts, component, model, prompt_hash, input_ref, output_hash, cached)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        [
            datetime.now(timezone.utc) - timedelta(minutes=30),
            "dest_classifier",
            "qwen2.5:7b",
            "hash_p_8849201",
            "megashare-demo.net",
            "hash_o_9918231",
            True
        ]
    )
    
    con.close()
    
    # Also save a backup copy as demo_seed.duckdb
    demo_db_path = Path("data/demo_seed.duckdb")
    import shutil
    shutil.copyfile(target_db, demo_db_path)
    
    print(f"Golden seed DuckDB created successfully at {target_db} ({os.path.getsize(target_db)} bytes)")
    print(f"Demo seed created at {demo_db_path}")
    print(f"Users directory saved to {users_csv_path}")

if __name__ == "__main__":
    generate_golden_seed()
