import json
import os
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple
from pipeline.db import get_connection

DEFAULT_IDENTITY_PATH = os.getenv("IDENTITY_MAP_PATH", "data/identity_map.json")

class Pseudonymizer:
    def __init__(self, mapping_path: str = DEFAULT_IDENTITY_PATH):
        self.mapping_path = Path(mapping_path)
        self._name_to_pid: Dict[str, str] = {}
        self._pid_to_name: Dict[str, str] = {}
        self.load()

    def load(self) -> None:
        if self.mapping_path.exists():
            with open(self.mapping_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self._name_to_pid = data.get("name_to_pid", {})
                self._pid_to_name = {v: k for k, v in self._name_to_pid.items()}

    def save(self) -> None:
        os.makedirs(self.mapping_path.parent, exist_ok=True)
        with open(self.mapping_path, "w", encoding="utf-8") as f:
            json.dump({
                "name_to_pid": self._name_to_pid
            }, f, indent=2)

    def get_or_create(self, real_name: str, seed: Optional[int] = None) -> str:
        if real_name in self._name_to_pid:
            return self._name_to_pid[real_name]
        
        rng = random.Random(seed or hash(real_name))
        while True:
            candidate = f"U-{rng.randint(1000, 9999)}"
            if candidate not in self._pid_to_name:
                self._name_to_pid[real_name] = candidate
                self._pid_to_name[candidate] = real_name
                self.save()
                return candidate

    def get_pid(self, real_name: str) -> Optional[str]:
        return self._name_to_pid.get(real_name)

    def reveal(self, user_pid: str, actor: str, role: str, justification: str) -> Tuple[bool, str]:
        """
        RBAC protected reveal.
        Requires justification and logs the action into the audit table.
        Only 'Auditor', 'SecurityAdmin', or 'SOC_Lead' can reveal.
        """
        allowed_roles = {"Auditor", "SecurityAdmin", "SOC_Lead"}
        ts = datetime.now(timezone.utc).isoformat()
        
        if role not in allowed_roles:
            self._log_audit(ts, actor, role, "reveal_identity", user_pid, justification, "DENIED_UNAUTHORIZED_ROLE")
            return False, "Access Denied: Insufficient privileges to de-anonymize user."

        if not justification or len(justification.strip()) < 10:
            self._log_audit(ts, actor, role, "reveal_identity", user_pid, justification, "DENIED_INSUFFICIENT_JUSTIFICATION")
            return False, "Access Denied: Detailed audit justification required (minimum 10 characters)."

        real_name = self._pid_to_name.get(user_pid)
        if not real_name:
            self._log_audit(ts, actor, role, "reveal_identity", user_pid, justification, "ERROR_PID_NOT_FOUND")
            return False, f"Error: Pseudonym {user_pid} not found in secure identity vault."

        self._log_audit(ts, actor, role, "reveal_identity", user_pid, justification, "APPROVED")
        return True, real_name

    def _log_audit(self, ts: str, actor: str, role: str, action: str, target: str, justification: str, result: str):
        try:
            con = get_connection()
            con.execute(
                """
                INSERT INTO audit (ts, actor, role, action, target, justification, result)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [ts, actor, role, action, target, justification, result]
            )
            con.close()
        except Exception:
            pass

_default_pseudonymizer: Optional[Pseudonymizer] = None

def get_pseudonymizer() -> Pseudonymizer:
    global _default_pseudonymizer
    if _default_pseudonymizer is None:
        _default_pseudonymizer = Pseudonymizer()
    return _default_pseudonymizer
