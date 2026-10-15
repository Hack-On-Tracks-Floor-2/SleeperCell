# InsiderLens Held-Out Evaluation Scenarios (Blind Test Set)

> **Split:** `split=heldout`  
> **Notice:** These scenarios are reserved strictly for blind evaluation to measure generalization across unexpected insider attack vectors and complex benign edge-cases.

---

### Scenario H-01: Disgruntled DevOps Engineer Token & Artifact Exfiltration
- **Role:** Ops / Site Reliability Engineer
- **Description:** A senior DevOps engineer whose promotion was passed over accesses the internal Vault cluster over a weekend, extracts production TLS private keys and AWS root credentials, then encodes them into multipart base64 chunks uploaded to an ephemeral paste site (`paste-drop-secure.xyz`).
- **Ground Truth:** Malicious (Stage: Collection & Exfiltration, Protocol: HTTPS).

---

### Scenario H-02: Cloud Data Pipeline Migration (Benign Hard Negative)
- **Role:** Dev / Data Engineer
- **Description:** An authorized data engineer performs an unscheduled database replication from on-prem PostgreSQL to Amazon RDS. Outbound transfer reaches 14GB over 6 hours during normal working hours with a matching Jira maintenance ticket `DATA-5501`.
- **Ground Truth:** Benign (Hard Negative - high volume, expected SaaS destination).

---

### Scenario H-03: Low-and-Slow Document Drip
- **Role:** Sales / Account Executive
- **Description:** An account executive planning to join a direct competitor systematically downloads 30 customer contract PDFs every evening between 7 PM and 8 PM, transmitting them as small 15MB HTTPS payloads to a personal ProtonDrive account over 21 consecutive days.
- **Ground Truth:** Malicious (Stage: Exfiltration, Low-and-Slow drip pattern).

---

### Scenario H-04: DNS Tunnelling Covert Channel
- **Role:** Finance / Junior Analyst
- **Description:** Compromised endpoint or rogue employee installs an iodine-based DNS tunnel client, encoding compressed customer billing spreadsheets into high-entropy Base32 subdomains (`*.tunnel.darknet-relay.su`) at 120 queries per minute without generating any direct HTTP/HTTPS connections.
- **Ground Truth:** Malicious (Hard Indicator: DNS Entropy & Subdomain Query Rate).

---

### Scenario H-05: Off-Hours Emergency Incident Hotfix (Benign Hard Negative)
- **Role:** Dev / Lead Architect
- **Description:** Emergency critical security patch pushed at 3:15 AM on a Saturday. Architect clones 3GB of dependencies and base containers from Docker Hub and GitHub, pushing hotfix binaries to internal production clusters.
- **Ground Truth:** Benign (Hard Negative - off-hours, high volume, sanctioned destinations).
