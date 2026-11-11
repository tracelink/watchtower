CREATE TABLE aws_security_rules (
    rule_id BIGINT NOT NULL PRIMARY KEY,
    profile VARCHAR(64) NOT NULL,
    CONSTRAINT fk_aws_security_rule FOREIGN KEY (rule_id) REFERENCES rules(rule_id)
);
CREATE TABLE aws_security_repository_settings (
    repository_id BIGINT NOT NULL PRIMARY KEY, version BIGINT NOT NULL DEFAULT 0,
    permission VARCHAR(16) NOT NULL, profile VARCHAR(64) NOT NULL,
    updated_by VARCHAR(255), updated_at BIGINT NOT NULL DEFAULT 0,
    readiness_at BIGINT NOT NULL DEFAULT 0, readiness_ok BOOLEAN NOT NULL DEFAULT FALSE, readiness_reason VARCHAR(512)
);
CREATE TABLE aws_security_permit (id INT NOT NULL PRIMARY KEY, run_id VARCHAR(36));
INSERT INTO aws_security_permit (id) VALUES (1);
CREATE TABLE aws_security_scan_runs (
    id VARCHAR(36) NOT NULL PRIMARY KEY, version BIGINT NOT NULL DEFAULT 0,
    execution_key VARCHAR(64) NOT NULL UNIQUE, parent_type VARCHAR(24) NOT NULL,
    parent_id BIGINT NOT NULL, repository_id BIGINT NOT NULL, snapshot_json TEXT NOT NULL,
    stage VARCHAR(24) NOT NULL, owner VARCHAR(36), fence BIGINT NOT NULL DEFAULT 0,
    lease_until BIGINT NOT NULL DEFAULT 0, created_at BIGINT NOT NULL, due_at BIGINT NOT NULL,
    deadline_at BIGINT NOT NULL, terminal_at BIGINT NOT NULL DEFAULT 0,
    dispatch_pending BOOLEAN NOT NULL DEFAULT FALSE, stop_requested BOOLEAN NOT NULL DEFAULT FALSE,
    needs_reconciliation BOOLEAN NOT NULL DEFAULT FALSE, provider_terminal BOOLEAN NOT NULL DEFAULT FALSE,
    provider_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    review_id VARCHAR(128), job_id VARCHAR(128), provider_status VARCHAR(64), status_reason VARCHAR(256),
    source_key VARCHAR(255), source_version VARCHAR(1024), source_sha VARCHAR(64), source_bytes BIGINT NOT NULL DEFAULT 0,
    source_files INT NOT NULL DEFAULT 0, diff_key VARCHAR(255), diff_version VARCHAR(1024), diff_sha VARCHAR(64),
    diff_index_key VARCHAR(255), diff_bytes BIGINT NOT NULL DEFAULT 0, cleanup_complete BOOLEAN NOT NULL DEFAULT FALSE,
    cleanup_attempts INT NOT NULL DEFAULT 0, artifact_key VARCHAR(255), imported_count INT NOT NULL DEFAULT 0,
    missing_count INT NOT NULL DEFAULT 0, aggregate_published BOOLEAN NOT NULL DEFAULT FALSE, scm_attempted BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX ix_aws_security_parent ON aws_security_scan_runs (parent_type, parent_id);
CREATE INDEX ix_aws_security_due ON aws_security_scan_runs (due_at);
CREATE INDEX ix_aws_security_job ON aws_security_scan_runs (job_id);
CREATE TABLE aws_security_audit (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY, action VARCHAR(64) NOT NULL,
    actor VARCHAR(255) NOT NULL, resource_id VARCHAR(64) NOT NULL, occurred_at BIGINT NOT NULL
);
