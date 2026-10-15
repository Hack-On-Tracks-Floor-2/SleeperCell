# InsiderLens: Evaluation Results & Benchmarks

> **Milestone:** Push 1 (Foundations & Golden Seed Baseline)  
> **Updated:** Thu 15 Oct, T+3h

---

## 1. Golden Seed Telemetry Summary
- **Simulated Population:** 5 enterprise personas across 5 departments (Finance, Dev, HR, Sales, Ops).
- **Duration:** 14 simulated days.
- **Total Flows Synthesized:** 1,467 encrypted flows.
- **Active Scenarios:** 1 ground-truth malicious insider attack (`resigning_finance_cloud_exfil`).
  - Stage 2: Collection / Document staging (1500 MB internal SharePoint access).
  - Stage 3: Nighttime bulk exfiltration (1800 MB burst to `megashare-demo.net` at 02:25 UTC).

---

## 2. Push 1 Sensor & Triage Metrics

| Metric | Target | Push 1 Status |
|---|---|---|
| Sensor Alerts Generated | 2 | 2 (ALT-0101, ALT-0102) |
| Case Risk Score | >= 75 (Critical) | **88.5 (Critical)** |
| Narrative Fidelity | 100% | **100.0% Verified** |
| Identity Vault Isolation | Real names segregated | **Enforced (Pseudonym U-xxxx)** |
| Destination Classifier Accuracy | > 90% | **100% on 10 benchmark domains** |
