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
### GenAI & RAG Layer (Ollama + ChromaDB + SentenceTransformers)
- **RAG Pipeline**: Vector search over security policies, playbooks, detection methodology, and live detection data
- **Source Citations**: Cites specific policy sections and evidence chunks
- **Hallucination Control**: Strict grounding with explicit refusal for out-of-context questions
- **Alert Explainer**: Plain-language narratives translating ML features into human stories
- **Incident Report Generator**: Automated markdown reports with kill-chain assessment
- **Graceful Fallbacks**: Intelligent template-based response engine when Ollama is offline
---

## 🚀 Quick Start
### Prerequisites
- Python 3.11+
- (Optional) [Ollama](https://ollama.ai) with `qwen2.5:7b-instruct` (or `llama3.1:8b`)
### Step 1: Create Virtual Environment
```bash
py -3.11 -m venv .venv
.venv\Scripts\activate
```
### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```
### Step 3: (Optional) Pull Ollama Model
```bash
ollama pull qwen2.5:7b-instruct
```
### Step 4: Run the Detection & RAG Pipeline
```bash
python run_pipeline.py
```
### Step 5: Launch the Modern Web Application (Recommended)
```bash
python api.py
```
Then navigate to `http://127.0.0.1:8000` to access the full-featured, responsive **InsiderLens** application.

### Step 6: (Alternative) Legacy Streamlit Dashboard
```bash
streamlit run dashboard.py
```
---
## 📊 Dashboard Pages
| Page | Description |
|------|-------------|
| 🏠 Overview | Risk heatmap, top alerts, detector distribution, daily volumes |
| ⚠️ Alerts & Cases | Kill-chain correlated cases with AI explanations & report downloads |
| 👤 User Analysis | Per-user baseline comparison, Z-score trends, hourly activity |
| 🤖 AI Copilot | Policy-grounded RAG chat with source citations & hallucination control |
| 📊 Analytics | Detection analysis, SHAP feature importance, network graph |
| 🔒 Privacy & Audit | Privacy controls, audit log, identity reveal requests |
| 🎯 Threat Simulator | Interactive attack simulator (DNS tunnel, cloud burst, low-and-slow) |
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
├── data/                    # Synthetic flow & user dataset
├── insiderlens/             # Core detection & AI modules
│   ├── config.py            # Configuration
│   ├── pipeline.py          # Data ingestion & enrichment
│   ├── detectors.py         # 6 detection models (XGBoost, IForest, DNS, etc.)
│   ├── risk_engine.py       # Decaying risk scoring & case correlation
│   ├── rag.py               # ChromaDB + SentenceTransformers RAG pipeline
│   └── genai_layer.py       # Ollama integration & grounded copilot
├── policies/                # Security policies & IR playbooks (RAG indexed)
│   ├── acceptable_use_policy.md
│   ├── detection_methodology.md
│   └── incident_response_playbook.md
├── results/                 # Pipeline outputs (CSVs, SHAP, JSONs)
├── reports/                 # Incident reports (generated Markdown)
├── models/                  # Trained models (XGBoost JSON)
├── frontend/                # Modern SPA web frontend
│   ├── index.html           # Semantic, accessible HTML5 layout
│   ├── styles.css           # Premium dark-mode design system & CSS variables
│   └── app.js               # Reactive vanilla JS application & Plotly charts
├── run_pipeline.py          # Main 7-step orchestrator
├── dashboard.py             # Streamlit interactive UI (legacy)
├── api.py                   # FastAPI REST backend & static web server
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