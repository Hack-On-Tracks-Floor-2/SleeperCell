# InsiderLens 🔍

> *"We don't read your data. We read your behavior, and we explain it in plain English."*

## Detecting Insider Data Leaks in Encrypted Traffic — Without Decrypting It

InsiderLens is a privacy-preserving, behavior-based insider threat detection platform that analyzes encrypted network traffic metadata to detect data exfiltration without any content decryption.

---

## 🏗️ Architecture

```
Raw Encrypted Traffic → Metadata Only → Features → Multiple Detectors
→ Per-User Risk & Kill-Chain Cases → LLM Narrative + Copilot + Report → Analyst Decision
```

### Detection Engine (6 Detectors)
1. **Flow Classifier** (XGBoost) - Identifies exfiltration-like flows
2. **User Anomaly Detector** (Isolation Forest) - Per-user and peer-group baselines
3. **DNS Tunnel Detector** - Statistical features for DNS tunneling
4. **Beaconing Detector** - Periodic callback pattern detection
5. **Low-and-Slow Detector** (CUSUM/EWMA) - Gradual data drip detection
6. **Volume Anomaly Detector** - Z-score deviation analysis

### GenAI Layer (Ollama + Qwen 2.5)
- Alert explainer (plain-language narratives)
- Analyst copilot (natural-language hunting)
- Incident report generator
- Template-based fallbacks when LLM unavailable

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- (Optional) [Ollama](https://ollama.ai) for AI-powered explanations

### Step 1: Create Virtual Environment
```bash
py -3.11 -m venv .venv
.venv\Scripts\activate
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: (Optional) Install Ollama + Model
```bash
# Download Ollama from https://ollama.ai
# Then pull the model:
ollama pull qwen2.5:7b
```

### Step 4: Run the Detection Pipeline
```bash
python run_pipeline.py
```

### Step 5: Launch the Dashboard
```bash
streamlit run dashboard.py
```

### Step 6: (Optional) Launch the API
```bash
python api.py
```

---

## 📊 Dashboard Pages

| Page | Description |
|------|-------------|
| 🏠 Overview | Risk heatmap, top alerts, detector distribution, daily volumes |
| ⚠️ Alerts & Cases | Kill-chain correlated cases with AI explanations |
| 👤 User Analysis | Per-user baseline comparison, Z-score trends, hourly activity |
| 🤖 AI Copilot | Natural-language threat hunting chat interface |
| 📊 Analytics | Detection analysis, SHAP importance, network graph |
| 🔒 Privacy & Audit | Privacy controls, audit log, identity reveal requests |

---

## 🔒 Privacy by Design

- **No Decryption**: Only metadata analyzed
- **Pseudonymization**: All user IDs pseudonymized
- **Gated Reveal**: De-anonymization requires HIGH risk + approval
- **Audit Trail**: Every query logged
- **Human-in-the-Loop**: System recommends, humans decide

---

## 📁 Project Structure

```
hack_try/
├── data/                    # Synthetic dataset
├── insiderlens/             # Core detection modules
│   ├── config.py            # Configuration
│   ├── pipeline.py          # Data ingestion & enrichment
│   ├── detectors.py         # 6 detection models
│   ├── risk_engine.py       # Risk scoring & correlation
│   └── genai_layer.py       # LLM integration
├── results/                 # Pipeline outputs (generated)
├── reports/                 # Incident reports (generated)
├── models/                  # Trained models (generated)
├── policies/                # Mock security policies
├── run_pipeline.py          # Main orchestrator
├── dashboard.py             # Streamlit dashboard
├── api.py                   # FastAPI backend
└── requirements.txt         # Dependencies
```

---

## 🧪 Dataset

Synthetic dataset with 10 users, 2900 flows over 14 days, including:
- **Normal activity** baseline
- **Gradual outbound increase** (USER-003)
- **Unusual destination burst** (USER-007)
- **Repeated after-hours activity** (USER-009)

---

## 📈 What Makes Us Different

1. ✅ Works without decrypting - only metadata
2. ✅ Per-user + peer-group baselines
3. ✅ Low-and-slow cumulative detection (30/90-day windows)
4. ✅ Kill-chain correlation into narrative cases
5. ✅ GenAI-driven explanations in plain English
6. ✅ Privacy-by-design with pseudonymization
7. ✅ Built-in synthetic attack scenarios
8. ✅ Analyst feedback loop

---

*Built for the 24-hour hackathon — Team SleeperCel*
