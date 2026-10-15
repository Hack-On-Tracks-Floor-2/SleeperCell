# Scenario Contract Specification (Frozen at Push 1)

## 1. Overview
This document specifies the exact YAML interface agreed between **Dev B** (Compiler / GenAI) and **Dev A** (Deterministic Simulator Engine).

## 2. Canonical YAML Schema
```yaml
scenario_id: resigning_finance_cloud_exfil
description: "Finance employee on notice stages client files, uploads to personal cloud at night"
actor:
  role: Finance
  count: 1
  flags: [notice_period]
phases:
  - stage: collection
    start_day: 18
    duration_days: 2
    internal_read_mb_per_day: 1500
    hours: [10, 18]
  - stage: exfiltration
    start_day: 20
    duration_days: 1
    upload_mb: 1800
    hours: [1, 3]
    destination:
      domain: "megashare-demo.net"
      category: cloud_storage
      first_seen: true
    protocol: https
    pattern: burst            # burst | drip | tunnel
evasion:
  padding: 0.0
  jitter: 0.0
  chunk_mb: null
labels:
  is_malicious: true
  split: train               # train | test | heldout
```

## 3. Data Dictionary
- `actor.role`: Role string matching persona definitions in `sim/personas.py`.
- `phases[].stage`: Must be one of `access`, `collection`, `exfiltration`, `cover_up`.
- `phases[].pattern`: Must be one of `burst`, `drip`, `tunnel`, `normal`.
- `destination.category`: Enum output matching destination classifier taxonomy.
- `labels.split`: One of `train`, `test`, `heldout`.
