#  InsiderLens

> **"Encrypted traffic hides content, not behaviour. ML sensors score the behaviour. A GenAI analyst investigates, explains and tests it, without ever decrypting a byte."**

InsiderLens is an enterprise behavioral security platform designed for modern Security Operations Centers (SOC). It detects malicious insider data staging and exfiltration across end-to-end encrypted networks without breaking TLS, intercepting keys, or inspecting private payloads.

---

##  Problem Statement & Threat Model

- **The Blindspot:** Enterprise network traffic is >95% encrypted (TLS 1.3, HTTPS). Traditional Data Loss Prevention (DLP) tools that rely on cleartext pattern matching or intrusive SSL decryption are blind or legally prohibited in privacy-conscious organizations.
- **The Insider Advantage:** Legitimate insiders already hold credentials, system access, and business justification. Attacks rarely use noisy malware; instead, they abuse authorized channels (SharePoint, AWS, personal clouds, paste sites) during notice periods or off-hours.
- **Our Defense:** Content is concealed, but behavioral geometry (transfer volume, direction ratios, timing, burst cadence, rare destinations, and internal staging) cannot be hidden.

---

##  System Architecture

```
 L1  SIMULATION (GenAI-Assisted)
     English Scenario ──> [Scenario Compiler] ──> scenario.yaml (Pydantic Validated)
     Personas + Hard Negatives + Evasion ──> Deterministic Seeded Engine
              │
              ▼   flows.parquet, dns_events, users_directory.csv, tickets.json
 L2  PIPELINE & ENRICHMENT
     Pseudonymize (U-xxxx) ──> Static Intel + [LLM Destination Classifier] (Cached)
     [LLM Context Extractor] ──> Structured `context` Rows (Notice periods, Maintenance)
              │
              ▼
 L3  BEHAVIORAL FEATURES
     Flow Stats │ 1d/7d/30d Windows │ Z-Score vs Self │ Peer Percentile │ Event Tokens
              │
              ▼
 L4  SENSORS (Auditable Numeric Scores + Evidence Tags)
     A. Flow Classifier        XGBoost + SHAP Top Features
     B. Behaviour LM           Event Token Surprisal (Fallback: Isolation Forest)
     C. Low-and-Slow           CUSUM / EWMA 30-Day Window Horizon
     D. Hard Indicators        DNS Entropy & High-Rate Tunneling Rule
              │
              ▼
 L5  RISK ENGINE
     Decayed Risk (Half-life: 7d) │ Context Multipliers │ Kill-Chain Staging (1-4)
              │
              ▼
 L6  GenAI ANALYST (Bounded, Logged, Verified)
     [Investigation Agent]     Tool-calling ──> Verdict, Priority Delta (±1 Band), Evidence IDs
     [Explainer + Verifier]    Narrative strictly verified against evidence JSON
     [Tool-calling Copilot]    6 Fixed read-only analytical functions
              │
              ▼
 L7  SOC API (FastAPI) + UI (Streamlit Dark Glassmorphism)
     Alert Feed │ Case Drilldown │ Baseline vs Actual │ Privacy Reveal │ Sandbox Launcher
```

---

##  The Trust Boundary

To remain defensible in high-assurance enterprise security environments, InsiderLens enforces hard architectural boundaries between statistical detection and generative reasoning:

| Layer | Component | Operating Rule |
|---|---|---|
| **Detection Scores** | Statistical & ML Models | **Never produced by an LLM.** Completely auditable and reproducible. |
| **Hard Indicators** | DNS Tunnel Rule | The LLM can annotate, but **cannot suppress or downgrade** hard indicators. |
| **Triage Verdict** | GenAI Agent | Moves priority by **at most one band** (-1, 0, +1). Initial and final bands are logged. |
| **Narrative Fidelity**| Explainer & Verifier | Every entity, number, and timestamp is verified against evidence JSON. |
| **Employee Identity** | Pseudonym Map | The LLM **never sees real names** (only `U-xxxx`). Identity de-anonymization requires RBAC and is audit-logged. |

---

##  Open On-Prem LLM Architecture

InsiderLens is built to run entirely on **self-hosted open-weights models**, ensuring sensitive telemetry never leaves the enterprise boundary:

- **Primary Models:**
  - **Fast Extraction & Classification:** **Qwen 2.5 7B** (or Llama 3.2 3B)
  - **Investigation & Reasoning:** **Qwen 2.5 14B** (or Llama 3.1 8B)
- **Local Runtime:** Compatible with **Ollama**, **vLLM**, or any local OpenAI-compatible endpoint (`http://localhost:11434/v1`).
- **Resilience:** Built-in disk caching, automatic schema retry, prompt-injection isolation wrappers (`<UNTRUSTED_DATA>`), and deterministic offline mode (`LLM_OFFLINE=1`).

---

##  Repository Structure

```
Team_SleeperCel/
├── README.md               # Project documentation and architecture guide
├── Makefile                # Build, run, and evaluation targets
├── requirements.txt        # Python dependency manifest
├── .env.example            # Environment configuration template
├── run_demo.py             # One-step demo launcher
├── data/
│   ├── golden_seed.duckdb  # 5-user, 14-day pre-computed DuckDB database
│   ├── demo_seed.duckdb    # Offline demo database backup
│   └── synthetic/
│       └── users_directory.csv # Anonymized user directory
├── sim/
│   ├── scenario_schema.py  # Pydantic schema for scenario YAML
│   ├── personas.py         # 5 enterprise personas (Finance, Dev, HR, Sales, Ops)
│   ├── engine.py           # Deterministic simulation & flow synthesis engine
│   └── scenarios/
│       └── resigning_finance_cloud_exfil.yaml # Canonical attack YAML
├── pipeline/
│   ├── schema.sql          # Core 12-table DuckDB SQL schema
│   ├── db.py               # Database connection and table initializer
│   └── pseudonymize.py     # Identity isolation vault with RBAC reveal
├── genai/
│   ├── llm_client.py       # On-prem open LLM client with cache & guardrails
│   └── dest_classifier.py  # Destination domain classifier with static cache
├── api/
│   └── main.py             # FastAPI backend (/health, /alerts, /cases, /privacy)
├── ui/
│   └── app.py              # Streamlit SOC dashboard with dark glassmorphism
├── eval/
│   ├── domains_labeled.csv # 100 labeled benchmark domains
│   ├── tickets.json        # HR/IT notes including prompt-injection tests
│   ├── copilot_questions.json # 20 copilot benchmark questions
│   └── heldout_scenarios.md# 5 blind held-out evaluation scenarios
└── tests/
    └── test_push1_contracts.py # Push 1 contract and schema verification tests
```

---

##  Quickstart Guide

### 1. Prerequisites
- Python 3.11+
- (Optional for live LLM inference) Local [Ollama](https://ollama.ai/) with `qwen2.5:7b`:
  ```bash
  ollama pull qwen2.5:7b
  ```

### 2. Installation
```bash
pip install -r requirements.txt
```

### 3. Launch Demo (Push 1 Gate)
Run the one-click demo launcher:
```bash
python run_demo.py
# or using Makefile:
make demo
```
This script validates the golden seed, runs the destination classifier contract test, and launches the **Streamlit SOC UI** at `http://localhost:8501`.

### 4. Run API Backend
```bash
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```
Access interactive OpenAPI documentation at `http://localhost:8000/docs`.

### 5. Run Verification Tests
```bash
python -m unittest tests/test_push1_contracts.py
```

---
