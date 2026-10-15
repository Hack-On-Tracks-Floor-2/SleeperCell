-- ==============================================================================
-- InsiderLens DuckDB Core Schema
-- ==============================================================================

-- Network traffic flows (Zeek-style flow records, no payload)
CREATE TABLE IF NOT EXISTS flows (
    flow_id VARCHAR PRIMARY KEY,
    ts_start TIMESTAMP NOT NULL,
    ts_end TIMESTAMP NOT NULL,
    user_pid VARCHAR NOT NULL,
    dst_ip VARCHAR NOT NULL,
    dst_port INTEGER NOT NULL,
    proto VARCHAR NOT NULL,
    bytes_out BIGINT NOT NULL,
    bytes_in BIGINT NOT NULL,
    pkts_out INTEGER NOT NULL,
    pkts_in INTEGER NOT NULL,
    duration DOUBLE NOT NULL,
    sni VARCHAR,
    ja4 VARCHAR,
    tls_version VARCHAR,
    cert_self_signed BOOLEAN DEFAULT FALSE,
    dst_asn VARCHAR,
    dst_country VARCHAR,
    domain_age_days INTEGER,
    dst_category VARCHAR,
    split VARCHAR DEFAULT 'train',
    is_malicious_gt BOOLEAN DEFAULT FALSE
);

-- DNS query events (for entropy/tunneling detection)
CREATE TABLE IF NOT EXISTS dns_events (
    ts TIMESTAMP NOT NULL,
    user_pid VARCHAR NOT NULL,
    qname VARCHAR NOT NULL,
    qtype VARCHAR NOT NULL,
    resp_size INTEGER NOT NULL,
    rcode VARCHAR NOT NULL
);

-- Daily behavioral aggregates per user
CREATE TABLE IF NOT EXISTS user_features_daily (
    user_pid VARCHAR NOT NULL,
    date DATE NOT NULL,
    role VARCHAR NOT NULL,
    dept VARCHAR NOT NULL,
    bytes_out_total BIGINT NOT NULL,
    n_ext_dest INTEGER NOT NULL,
    n_new_dest INTEGER NOT NULL,
    upload_ratio DOUBLE NOT NULL,
    offhours_share DOUBLE NOT NULL,
    internal_read_bytes BIGINT NOT NULL,
    z_vs_self DOUBLE NOT NULL,
    pct_vs_peer DOUBLE NOT NULL,
    cum_out_7d BIGINT NOT NULL,
    cum_out_30d BIGINT NOT NULL,
    PRIMARY KEY (user_pid, date)
);

-- Event tokens for sequence modeling / surprisal
CREATE TABLE IF NOT EXISTS event_tokens (
    user_pid VARCHAR NOT NULL,
    ts TIMESTAMP NOT NULL,
    token_id INTEGER NOT NULL,
    token_str VARCHAR NOT NULL
);

-- Domain intelligence cache
CREATE TABLE IF NOT EXISTS dest_intel (
    domain VARCHAR PRIMARY KEY,
    category VARCHAR NOT NULL,
    confidence DOUBLE NOT NULL,
    source VARCHAR NOT NULL, -- 'static' or 'llm'
    classified_at TIMESTAMP NOT NULL
);

-- Structured organizational context (tickets, HR notes, maintenance windows)
CREATE TABLE IF NOT EXISTS context (
    context_id VARCHAR PRIMARY KEY,
    subject VARCHAR NOT NULL,
    type VARCHAR NOT NULL,
    start TIMESTAMP NOT NULL,
    "end" TIMESTAMP NOT NULL,
    expected_destinations VARCHAR, -- comma-separated or JSON string
    expected_volume_mb DOUBLE,
    source_ticket_id VARCHAR
);

-- Sensor alerts
CREATE TABLE IF NOT EXISTS alerts (
    alert_id VARCHAR PRIMARY KEY,
    ts TIMESTAMP NOT NULL,
    user_pid VARCHAR NOT NULL,
    detector VARCHAR NOT NULL,
    score DOUBLE NOT NULL,
    evidence_tags VARCHAR, -- JSON array
    top_features VARCHAR,  -- JSON dict
    stage VARCHAR NOT NULL,
    case_id VARCHAR
);

-- Correlated investigation cases
CREATE TABLE IF NOT EXISTS cases (
    case_id VARCHAR PRIMARY KEY,
    user_pid VARCHAR NOT NULL,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    risk_score DOUBLE NOT NULL,
    band VARCHAR NOT NULL, -- Low | Medium | High | Critical
    stages VARCHAR NOT NULL, -- Comma-separated or JSON list
    status VARCHAR DEFAULT 'OPEN'
);

-- GenAI Investigation Agent verdicts
CREATE TABLE IF NOT EXISTS case_verdicts (
    case_id VARCHAR PRIMARY KEY,
    verdict VARCHAR NOT NULL, -- escalate | monitor | likely_benign
    priority_delta INTEGER NOT NULL, -- -1 | 0 | 1
    reasoning VARCHAR NOT NULL,
    evidence_ids VARCHAR NOT NULL, -- JSON list
    confidence VARCHAR NOT NULL, -- low | medium | high
    model_band VARCHAR NOT NULL,
    final_band VARCHAR NOT NULL
);

-- Faithful verified explanations
CREATE TABLE IF NOT EXISTS narratives (
    case_id VARCHAR PRIMARY KEY,
    text VARCHAR NOT NULL,
    verified_pct DOUBLE NOT NULL,
    unverified_sentences VARCHAR -- JSON list
);

-- Immutable audit log (for identity reveal & analyst actions)
CREATE TABLE IF NOT EXISTS audit (
    ts TIMESTAMP NOT NULL,
    actor VARCHAR NOT NULL,
    role VARCHAR NOT NULL,
    action VARCHAR NOT NULL,
    target VARCHAR NOT NULL,
    justification VARCHAR,
    result VARCHAR NOT NULL
);

-- Auditable LLM call trail
CREATE TABLE IF NOT EXISTS llm_calls (
    ts TIMESTAMP NOT NULL,
    component VARCHAR NOT NULL,
    model VARCHAR NOT NULL,
    prompt_hash VARCHAR NOT NULL,
    input_ref VARCHAR,
    output_hash VARCHAR NOT NULL,
    cached BOOLEAN NOT NULL
);
