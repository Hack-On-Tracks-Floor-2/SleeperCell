# InsiderLens Detection Methodology & Knowledge Base

## 1. Detection Philosophy
InsiderLens detects insider data leaks in encrypted traffic WITHOUT decrypting content. The system analyzes network metadata — who, when, how much, to where, in what pattern — to identify exfiltration behavior. We never inspect payloads, file names, or message content.

## 2. What Is Visible in Encrypted Traffic

### 2.1 Network Layer (IP/TCP/UDP)
- Source and destination IP addresses and ports
- Protocol type (TCP, UDP, ICMP)
- Flow start and end times, duration
- Bytes and packets per direction (inbound vs outbound)
- TCP flags, retransmissions, idle periods

### 2.2 TLS Handshake
- Server Name Indication (SNI) — the hostname the client connects to
- TLS version and cipher suites
- JA3/JA4 fingerprints that identify the client software
- Certificate details: issuer, validity, self-signed status

### 2.3 DNS (when not encrypted)
- Queried domain names and record types
- Response sizes and frequencies
- Can reveal DNS tunneling through statistical analysis

### 2.4 Identity Mapping
- DHCP leases, VPN logs, and Active Directory map IPs to users
- HR records provide department, role, and employment status context

### 2.5 What We Do NOT Use
- Payload bytes or decrypted content
- File names, document text, or message bodies
- Email subject lines or attachment names
- URLs beyond the hostname (SNI/DNS)

## 3. Detection Engine — Six Specialized Detectors

### 3.1 Detector A: Flow Classifier (XGBoost)
**Purpose:** Classifies individual network flows as normal or exfiltration-like.
**Algorithm:** XGBoost gradient-boosted decision tree with SHAP explainability.
**Features used:**
- bytes_out, bytes_in: directional volume
- upload_ratio: bytes_out / (bytes_in + 1) — key exfiltration indicator
- duration_seconds: how long the flow lasted
- packets_out, packets_in: packet counts
- bytes_per_sec_out: transfer speed
- bytes_per_pkt_out: average packet size
- total_bytes: combined volume
- is_after_hours: flag for activity between 8 PM and 7 AM
- is_weekend: flag for Saturday/Sunday
- has_sni: whether TLS Server Name Indication is present
- dns_query_length: length of DNS query
- dns_query_entropy: Shannon entropy of DNS query (high entropy suggests encoding)
- is_new_destination: first-time communication with this IP

**Training:** Labeled using scenario tags (gradual_outbound_increase, unusual_destination_burst, repeated_after_hours_activity) plus heuristic labels for extreme upload ratios.
**Threshold:** Flows scoring above 0.3 probability generate alerts.

### 3.2 Detector B: User Anomaly Detector (Isolation Forest)
**Purpose:** Detects when a user's daily behavior deviates from their own baseline and their peer group.
**Algorithm:** Isolation Forest (unsupervised anomaly detection).
**Two-level approach:**
1. Global model: Fits all users, contamination=0.10, n_estimators=100
2. Per-department models: Fits users in the same department, contamination=0.15
**Combined score:** 60% global + 40% peer-group anomaly score.
**Features used:**
- total_bytes_out: daily aggregate outbound volume
- total_flows: number of connections per day
- unique_destinations: distinct external IPs contacted
- after_hours_ratio: proportion of after-hours activity
- mean_upload_ratio: average upload/download ratio
- max_bytes_out: largest single outbound burst
- new_destinations: count of first-time destinations
- mean_bytes_per_sec: average transfer rate

### 3.3 Detector D1: DNS Tunnel Detector
**Purpose:** Detects data exfiltration hidden inside DNS queries.
**Method:** Statistical feature analysis (no ML model needed).
**Indicators scored:**
- Query length > 50 characters (+0.3 score)
- Subdomain entropy > 4.0 bits (+0.3 score) — encoded data has high entropy
- More than 5 DNS labels (+0.2 score) — e.g., encoded.data.here.evil.com
- Large bytes on port 53 (+0.2 score)

### 3.4 Detector D2: Beaconing Detector
**Purpose:** Detects periodic, automated callbacks to external destinations (C2-style communication).
**Method:** Coefficient of Variation (CV) of inter-arrival times between connections.
**Scoring:**
- CV < 0.1: Very regular intervals → score 0.9 (strong beaconing)
- CV < 0.3: Regular intervals → score 0.6
- CV < 0.5: Somewhat regular → score 0.3
- Consistent payload sizes add +0.1

### 3.5 Detector E: Low-and-Slow Detector (CUSUM/EWMA)
**Purpose:** Catches gradual, persistent data exfiltration that never triggers single-day thresholds.
**Algorithms:**
- CUSUM (Cumulative Sum) control chart: Detects upward shifts in daily outbound volume. Parameters: k=0.5 (allowance), h=4.0 (threshold).
- EWMA (Exponentially Weighted Moving Average): Detects trends over a 5-day span with residual threshold of 2.0σ.
**Combined scoring:** CUSUM trigger adds +0.5, EWMA trigger adds +0.4.
**Window tracking:** Also checks 7-day cumulative bytes against 95th percentile.

### 3.6 Detector F: Volume Anomaly Detector
**Purpose:** Detects sudden volume spikes compared to self-history and peer group.
**Method:** Z-score analysis.
**Scoring:**
- |Z-score vs self| > 3: +0.5 (extreme deviation)
- |Z-score vs self| > 2: +0.3 (high deviation)
- |Z-score vs peer| > 3: +0.3 (extreme peer deviation)
- |Z-score vs peer| > 2: +0.15 (high peer deviation)
- After-hours ratio Z > 2: +0.2 (unusual timing)

## 4. Risk Scoring Engine

### 4.1 Per-User Risk Formula
```
risk(t) = risk(t-1) * exp(-lambda * dt) + sum(weight_i * score_i) * context_multiplier
```
- Lambda controls decay rate (half-life = 7 days = 168 hours)
- Risk accumulates with new evidence and decays during quiet periods

### 4.2 Detector Weights
| Detector | Weight | Rationale |
|----------|--------|-----------|
| DNS Tunneling | 20.0 | Covert channel, high confidence indicator |
| Low-and-Slow | 18.0 | Persistent exfiltration, hard to detect |
| Flow Classifier | 15.0 | ML-based, primary exfil detector |
| Volume Anomaly | 14.0 | Statistical deviation from baselines |
| User Anomaly | 12.0 | Behavioral deviation detection |
| Beaconing | 12.0 | C2 communication pattern |

### 4.3 Context Multipliers
| Context | Multiplier | Source |
|---------|-----------|--------|
| Departing employee (notice period) | 1.5x | HR records |
| Employee on leave | 1.3x | HR records |
| Contractor | 1.2x | Role classification |
| Privileged role (IT Admin, etc.) | 1.2x | Role classification |

### 4.4 Severity Bands
| Level | Score Range | Action |
|-------|------------|--------|
| INFO | < 20 | Log only |
| LOW | 20 - 40 | Add to watchlist |
| MEDIUM | 40 - 65 | Active monitoring, prepare investigation |
| HIGH | 65 - 85 | Investigate, prepare containment |
| CRITICAL | ≥ 85 | Immediate escalation and containment |

## 5. Kill-Chain Correlation

### 5.1 Insider Threat Kill Chain Stages
| Stage | Name | Example Signals |
|-------|------|----------------|
| 1 | Reconnaissance/Access | Unusual internal file-server access, new internal hosts contacted |
| 2 | Collection/Staging | Large internal reads, bulk downloads, compression activity |
| 3 | Exfiltration | Large/slow uploads, rare destinations, DNS tunnels, SSH to unknown hosts |
| 4 | Cover-up | Tor/VPN use, activity deletion, sudden silence after exfil |

### 5.2 Case Creation
A case is created when multiple alerts for the same user are correlated. Cases link alerts across kill-chain stages into a single narrative, reducing hundreds of alerts into a manageable number of investigation cases.

## 6. Feature Engineering Pipeline

### 6.1 Flow-Level Features (per connection)
- Upload ratio = bytes_out / (bytes_in + 1)
- Bytes per second (outbound and inbound)
- Packets per second
- Bytes per packet
- Total volume
- After-hours flag (8 PM - 7 AM)
- Weekend flag
- Destination categorization (cloud storage, webmail, unknown, etc.)
- Destination newness (first-time contact)
- DNS query entropy and length

### 6.2 User-Daily Aggregate Features
- Total bytes out, total flows, unique destinations
- Mean and max upload ratios
- New destinations count
- After-hours ratio, weekend flows
- TLS flow count, mean duration
- Cloud storage flow count

### 6.3 Baseline Deviation Features
- Per-user Z-scores: Compare today vs. 7-day rolling history
- Peer-group Z-scores: Compare today vs. same department average
- Peer-group percentile rank
- Cumulative bytes over 7-day and 14-day windows

## 7. Privacy-by-Design Architecture

### 7.1 Core Principles
- **No decryption:** Only metadata is collected and analyzed
- **Data minimization:** No payloads, file names, or URLs stored
- **Pseudonymization:** All user IDs appear as pseudonymous identifiers
- **Gated de-anonymization:** Revealing identity requires HIGH risk AND authorized approval
- **Audit trail:** Every query, reveal, and export is logged
- **Human-in-the-loop:** System recommends, humans decide

### 7.2 What the LLM Never Sees
- Real user names or employee IDs
- Payload content or decrypted data
- File names or document titles
- Raw IP addresses (unless pseudonymized)

## 8. Exfiltration Channels Detected

### 8.1 Cloud Storage Upload
Detected by: High upload ratio + cloud storage destination category + volume anomaly.
Examples: Google Drive, OneDrive, Dropbox, Mega, iCloud, WeTransfer.

### 8.2 Webmail Attachment
Detected by: Upload to webmail domains + unusual volume.
Examples: Gmail, Outlook, ProtonMail, Yahoo Mail.

### 8.3 DNS Tunneling
Detected by: Long DNS queries, high subdomain entropy, many DNS labels, large DNS payloads.
Tools detected: iodine, dnscat2, dns2tcp.

### 8.4 Command-and-Control (C2) Beaconing
Detected by: Regular inter-arrival times, consistent payload sizes, periodic callbacks.
Indicates: Compromised insider or automated exfiltration.

### 8.5 Low-and-Slow Data Drip
Detected by: CUSUM/EWMA change-point detection over 7-30 day windows.
Pattern: Small daily uploads that individually look normal but accumulate to significant volume.

### 8.6 Unsanctioned Protocols
Detected by: SSH/SCP to external hosts, unusual ports, unrecognized JA4 fingerprints.
