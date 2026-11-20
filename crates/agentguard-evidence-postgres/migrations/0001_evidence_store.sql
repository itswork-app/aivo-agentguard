CREATE TABLE IF NOT EXISTS agentguard_evidence_stream_heads (
    tenant_id TEXT NOT NULL,
    stream_id TEXT NOT NULL,
    last_sequence BIGINT NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    last_event_hash TEXT NOT NULL CHECK (last_event_hash ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (tenant_id, stream_id)
);

CREATE TABLE IF NOT EXISTS agentguard_evidence_events (
    tenant_id TEXT NOT NULL,
    stream_id TEXT NOT NULL,
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    event_id TEXT NOT NULL,
    previous_event_hash TEXT NOT NULL CHECK (previous_event_hash ~ '^[0-9a-f]{64}$'),
    event_hash TEXT NOT NULL CHECK (event_hash ~ '^[0-9a-f]{64}$'),
    payload_bytes BYTEA NOT NULL,
    committed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, stream_id, sequence),
    UNIQUE (tenant_id, stream_id, event_id),
    FOREIGN KEY (tenant_id, stream_id)
        REFERENCES agentguard_evidence_stream_heads (tenant_id, stream_id)
);

CREATE INDEX IF NOT EXISTS agentguard_evidence_events_tenant_event
    ON agentguard_evidence_events (tenant_id, event_id);
