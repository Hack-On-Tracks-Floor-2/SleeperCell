"""
InsiderLens Configuration Module
Central configuration for the entire system.
"""
import os
from pathlib import Path

# ── Project Paths ──────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data"
MODELS_DIR = PROJECT_ROOT / "models"
REPORTS_DIR = PROJECT_ROOT / "reports"
POLICIES_DIR = PROJECT_ROOT / "policies"

# Create directories if they don't exist
for d in [MODELS_DIR, REPORTS_DIR, POLICIES_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ── Detection Thresholds ──────────────────────────────────────────────
RISK_THRESHOLDS = {
    "low": 20.0,
    "medium": 40.0,
    "high": 65.0,
    "critical": 85.0,
}

# Risk score decay half-life in hours
RISK_HALF_LIFE_HOURS = 24 * 7  # 7 days

# Context multipliers
CONTEXT_MULTIPLIERS = {
    "departing_employee": 1.5,
    "on_leave": 1.3,
    "contractor": 1.2,
    "privileged_role": 1.2,
}

# Detector weights for risk scoring
DETECTOR_WEIGHTS = {
    "flow_classifier": 15.0,
    "user_anomaly": 12.0,
    "peer_anomaly": 10.0,
    "dns_tunnel": 20.0,
    "beaconing": 12.0,
    "low_and_slow": 18.0,
    "rare_destination": 10.0,
    "time_anomaly": 8.0,
    "volume_anomaly": 14.0,
}

# ── Feature Engineering ───────────────────────────────────────────────
BASELINE_WINDOW_DAYS = 7
LONG_WINDOW_DAYS = 30
AFTER_HOURS_START = 20  # 8 PM
AFTER_HOURS_END = 7     # 7 AM

# Cloud storage / suspicious domains
CLOUD_STORAGE_DOMAINS = [
    "drive.google", "dropbox", "mega.nz", "wetransfer",
    "onedrive", "icloud", "box.com", "mediafire",
    "sendspace", "zippyshare", "pastebin", "github.com/gist",
]

WEBMAIL_DOMAINS = [
    "gmail", "outlook", "protonmail", "yahoo.mail",
    "tutanota", "zoho.mail",
]

# ── GenAI Configuration ──────────────────────────────────────────────
# Use Ollama with qwen2.5:7b (best balance of quality and speed)
OLLAMA_MODEL = "qwen2.5:7b"
OLLAMA_BASE_URL = "http://localhost:11434"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

# ── API Configuration ────────────────────────────────────────────────
API_HOST = "0.0.0.0"
API_PORT = 8000
STREAMLIT_PORT = 8501

# ── Kill Chain Stages ────────────────────────────────────────────────
KILL_CHAIN_STAGES = {
    1: "Reconnaissance / Access",
    2: "Collection / Staging",
    3: "Exfiltration",
    4: "Cover-up",
}

# ── Privacy ──────────────────────────────────────────────────────────
PSEUDONYMIZE_USERS = True
REVEAL_THRESHOLD = "high"  # Minimum risk level to allow de-anonymization
