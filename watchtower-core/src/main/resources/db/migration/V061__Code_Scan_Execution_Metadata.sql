-- Execution evidence deliberately has no FK to mutable rule definitions. Legacy scans stay
-- unknown: their identity, policy and coverage cannot be reconstructed from current settings.
ALTER TABLE pull_request_violations ADD COLUMN execution_rule_id BIGINT NULL;
ALTER TABLE pull_request_violations ADD COLUMN rule_module VARCHAR(64) NULL;
ALTER TABLE pull_request_violations ADD COLUMN rule_revision VARCHAR(64) NULL;
ALTER TABLE pull_request_violations ADD COLUMN external_rule_key VARCHAR(255) NULL;
ALTER TABLE pull_request_violations ADD COLUMN rule_origin_key VARCHAR(255) NULL;
ALTER TABLE pull_request_violations ADD COLUMN engine_fingerprint VARCHAR(64) NULL;
ALTER TABLE pull_request_violations ADD COLUMN effective_blocking BOOLEAN NULL;
ALTER TABLE pull_request_violations ADD COLUMN final_blocking BOOLEAN NULL;
ALTER TABLE pull_request_violations ADD COLUMN new_finding BOOLEAN NULL;
ALTER TABLE pull_request_violations ADD COLUMN bypassed BOOLEAN NULL;

ALTER TABLE upload_violations ADD COLUMN execution_rule_id BIGINT NULL;
ALTER TABLE upload_violations ADD COLUMN rule_module VARCHAR(64) NULL;
ALTER TABLE upload_violations ADD COLUMN rule_revision VARCHAR(64) NULL;
ALTER TABLE upload_violations ADD COLUMN external_rule_key VARCHAR(255) NULL;
ALTER TABLE upload_violations ADD COLUMN rule_origin_key VARCHAR(255) NULL;
ALTER TABLE upload_violations ADD COLUMN engine_fingerprint VARCHAR(64) NULL;
ALTER TABLE upload_violations ADD COLUMN effective_blocking BOOLEAN NULL;
ALTER TABLE upload_violations ADD COLUMN final_blocking BOOLEAN NULL;
ALTER TABLE upload_violations ADD COLUMN new_finding BOOLEAN NULL;

CREATE INDEX idx_pr_violation_execution_rule
    ON pull_request_violations (execution_rule_id, rule_revision);
CREATE INDEX idx_upload_violation_execution_rule
    ON upload_violations (execution_rule_id, rule_revision);

ALTER TABLE pull_request_scans ADD COLUMN execution_snapshot_json LONGTEXT NULL;
ALTER TABLE upload_scans ADD COLUMN execution_snapshot_json LONGTEXT NULL;
ALTER TABLE repo_scans ADD COLUMN execution_snapshot_json LONGTEXT NULL;
