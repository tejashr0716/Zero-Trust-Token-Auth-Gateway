-- SentinelTrust: Zero-Trust Token Auth Gateway & Threat Detection Schema

DROP TABLE IF EXISTS access_audit_logs CASCADE;
DROP TABLE IF EXISTS threat_incidents CASCADE;
DROP TABLE IF EXISTS security_tokens CASCADE;
DROP TABLE IF EXISTS revocation_bloom_snapshots CASCADE;
DROP TABLE IF EXISTS services CASCADE;

CREATE TABLE services (
    service_id VARCHAR(64) PRIMARY KEY,
    service_name VARCHAR(128) NOT NULL,
    trust_level VARCHAR(32) NOT NULL DEFAULT 'RESTRICTED', -- PUBLIC, INTERNAL, RESTRICTED, CRITICAL
    ip_cidr VARCHAR(64) NOT NULL,
    public_key_pem TEXT,
    rate_limit_per_min INT NOT NULL DEFAULT 10000,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE security_tokens (
    token_id VARCHAR(64) PRIMARY KEY,
    client_id VARCHAR(64) NOT NULL,
    service_id VARCHAR(64) REFERENCES services(service_id) ON DELETE CASCADE,
    claims_json JSONB NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE threat_incidents (
    incident_id BIGSERIAL PRIMARY KEY,
    threat_type VARCHAR(64) NOT NULL, -- REPLAY_ATTACK, SIGNATURE_TAMPERING, IP_SPOOFING, BRUTE_FORCE, PRIVILEGE_ESCALATION
    severity VARCHAR(32) NOT NULL,    -- LOW, MEDIUM, HIGH, CRITICAL
    source_ip VARCHAR(64) NOT NULL,
    client_id VARCHAR(64) NOT NULL,
    threat_score DOUBLE PRECISION NOT NULL,
    action_taken VARCHAR(64) NOT NULL, -- QUARANTINED, BLOCKED, LOGGED_ONLY
    raw_evidence JSONB NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE access_audit_logs (
    log_id BIGSERIAL PRIMARY KEY,
    token_id VARCHAR(64) NOT NULL,
    client_id VARCHAR(64) NOT NULL,
    service_id VARCHAR(64) REFERENCES services(service_id) ON DELETE CASCADE,
    requested_endpoint VARCHAR(256) NOT NULL,
    decision VARCHAR(32) NOT NULL, -- ALLOWED, DENIED_REVOKED, DENIED_EXPIRED, DENIED_TAMPERED
    latency_us DOUBLE PRECISION NOT NULL,
    source_ip VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE revocation_bloom_snapshots (
    snapshot_id BIGSERIAL PRIMARY KEY,
    bitset_size INT NOT NULL,
    hash_count INT NOT NULL,
    total_revoked INT NOT NULL,
    filter_data BYTEA,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed Initial Zero-Trust Microservices
INSERT INTO services (service_id, service_name, trust_level, ip_cidr, rate_limit_per_min, status) VALUES
('svc_payment_core', 'Stripe Payment Processing Gateway', 'CRITICAL', '10.240.10.0/24', 50000, 'ACTIVE'),
('svc_order_engine', 'Apex Distributed Order Matching', 'CRITICAL', '10.240.12.0/24', 100000, 'ACTIVE'),
('svc_telemetry_hub', 'CloudSentinel Monitoring Mesh', 'INTERNAL', '10.240.20.0/24', 30000, 'ACTIVE'),
('svc_auth_broker', 'Enterprise Identity Provider', 'CRITICAL', '10.240.5.0/24', 60000, 'ACTIVE');

-- Seed Initial Security Tokens
INSERT INTO security_tokens (token_id, client_id, service_id, claims_json, issued_at, expires_at, revoked) VALUES
('tok_alpha_9981', 'client_worker_01', 'svc_payment_core', '{"role": "executor", "scope": "payments:write"}', NOW(), NOW() + INTERVAL '24 hours', FALSE),
('tok_beta_1142', 'client_batch_job', 'svc_order_engine', '{"role": "service", "scope": "orders:read"}', NOW(), NOW() + INTERVAL '12 hours', FALSE),
('tok_revoked_bad', 'client_rogue_bot', 'svc_auth_broker', '{"role": "anonymous", "scope": "admin:root"}', NOW() - INTERVAL '2 hours', NOW() + INTERVAL '1 hour', TRUE);

-- Seed Initial Threat Incidents
INSERT INTO threat_incidents (threat_type, severity, source_ip, client_id, threat_score, action_taken, raw_evidence) VALUES
('SIGNATURE_TAMPERING', 'CRITICAL', '198.51.100.42', 'client_rogue_bot', 98.5, 'QUARANTINED', '{"tampered_header": "alg:none", "target": "svc_auth_broker"}'),
('REPLAY_ATTACK', 'HIGH', '203.0.113.19', 'client_unknown_99', 85.0, 'BLOCKED', '{"nonce_replayed": "0xABCDEF887", "count": 14}');

-- Seed Initial Audit Logs
INSERT INTO access_audit_logs (token_id, client_id, service_id, requested_endpoint, decision, latency_us, source_ip) VALUES
('tok_alpha_9981', 'client_worker_01', 'svc_payment_core', '/api/v1/charge', 'ALLOWED', 14.5, '10.240.10.45'),
('tok_beta_1142', 'client_batch_job', 'svc_order_engine', '/api/v1/book', 'ALLOWED', 18.2, '10.240.12.8'),
('tok_revoked_bad', 'client_rogue_bot', 'svc_auth_broker', '/api/v1/admin/secrets', 'DENIED_REVOKED', 4.1, '198.51.100.42');

-- Synchronize sequences
SELECT setval('threat_incidents_incident_id_seq', (SELECT COALESCE(MAX(incident_id), 1) FROM threat_incidents));
SELECT setval('access_audit_logs_log_id_seq', (SELECT COALESCE(MAX(log_id), 1) FROM access_audit_logs));
SELECT setval('revocation_bloom_snapshots_snapshot_id_seq', (SELECT COALESCE(MAX(snapshot_id), 1) FROM revocation_bloom_snapshots));
