import os
import unittest
import yaml
from pathlib import Path

from sim.scenario_schema import Scenario
from pipeline.pseudonymize import Pseudonymizer
from pipeline.db import get_connection
from genai.dest_classifier import classify_destination, DestinationCategory

class TestPush1Contracts(unittest.TestCase):
    def test_scenario_yaml_schema_validation(self):
        """Validates that the canonical finance insider scenario passes strict Pydantic parsing."""
        yaml_path = Path("sim/scenarios/resigning_finance_cloud_exfil.yaml")
        self.assertTrue(yaml_path.exists(), "Scenario YAML file must exist")
        
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            
        scenario = Scenario.model_validate(data)
        self.assertEqual(scenario.scenario_id, "resigning_finance_cloud_exfil")
        self.assertEqual(scenario.actor.role, "Finance")
        self.assertEqual(len(scenario.phases), 2)
        self.assertEqual(scenario.phases[0].stage, "collection")
        self.assertEqual(scenario.phases[1].stage, "exfiltration")
        self.assertEqual(scenario.phases[1].destination.domain, "megashare-demo.net")
        self.assertTrue(scenario.labels.is_malicious)

    def test_pseudonymizer_isolation_and_rbac(self):
        """Verifies pseudonym creation, isolation, and RBAC-governed de-anonymization."""
        temp_map_path = "data/test_identity_map.json"
        if os.path.exists(temp_map_path):
            os.remove(temp_map_path)

        p = Pseudonymizer(mapping_path=temp_map_path)
        pid = p.get_or_create("Elena Rostova")
        self.assertTrue(pid.startswith("U-"))
        self.assertEqual(p.get_or_create("Elena Rostova"), pid) # Idempotent

        # Unauthorized role test
        ok, msg = p.reveal(pid, actor="intern", role="Intern", justification="Curiosity")
        self.assertFalse(ok)
        self.assertIn("Insufficient privileges", msg)

        # Insufficient justification test
        ok, msg = p.reveal(pid, actor="lead", role="SOC_Lead", justification="short")
        self.assertFalse(ok)
        self.assertIn("justification required", msg)

        # Valid reveal test
        ok, real_name = p.reveal(
            pid,
            actor="lead",
            role="SOC_Lead",
            justification="Escalated critical incident exfiltration investigation ALT-0102"
        )
        self.assertTrue(ok)
        self.assertEqual(real_name, "Elena Rostova")

        if os.path.exists(temp_map_path):
            os.remove(temp_map_path)

    def test_destination_classifier_contract(self):
        """Verifies destination classifier returns valid categories and confidence."""
        res = classify_destination("dropbox.com")
        self.assertEqual(res.category, DestinationCategory.CLOUD_STORAGE)
        self.assertGreaterEqual(res.confidence, 0.9)

    def test_golden_seed_database_integrity(self):
        """Verifies all required DuckDB tables exist and contain seeded data."""
        con = get_connection(read_only=True)
        tables = [
            "flows", "dns_events", "user_features_daily", "event_tokens",
            "dest_intel", "context", "alerts", "cases", "case_verdicts",
            "narratives", "audit", "llm_calls"
        ]
        db_tables = [r[0] for r in con.execute("SHOW TABLES").fetchall()]
        for t in tables:
            self.assertIn(t, db_tables, f"Table {t} must be present in schema")
            
        case_count = con.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
        self.assertGreaterEqual(case_count, 1)
        con.close()

if __name__ == "__main__":
    unittest.main()
