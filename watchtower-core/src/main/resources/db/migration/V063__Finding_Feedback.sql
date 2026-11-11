CREATE TABLE finding_feedback (
 occurrence_key CHAR(64) NOT NULL PRIMARY KEY, scan_type VARCHAR(24) NOT NULL,
 scan_id BIGINT NOT NULL, finding_key VARCHAR(64) NOT NULL, rule_id BIGINT NULL,
 revision VARCHAR(64) NULL, effective_blocking BOOLEAN NULL, occurred_at BIGINT NOT NULL,
 judgment VARCHAR(24) NOT NULL, disposition VARCHAR(24) NOT NULL,
 explanation VARCHAR(300) NOT NULL, reviewer VARCHAR(255) NOT NULL,
 updated_at BIGINT NOT NULL, version BIGINT NOT NULL,
 INDEX idx_feedback_rule (rule_id, revision, occurred_at), INDEX idx_feedback_scan (scan_type, scan_id)
);
CREATE TABLE finding_feedback_audit (
 audit_id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY, occurrence_key CHAR(64) NOT NULL,
 judgment VARCHAR(24) NOT NULL, disposition VARCHAR(24) NOT NULL,
 explanation VARCHAR(300) NOT NULL, reviewer VARCHAR(255) NOT NULL, changed_at BIGINT NOT NULL,
 INDEX idx_feedback_audit (occurrence_key, changed_at)
);
ALTER TABLE pull_request_bypasses ADD COLUMN reason_code VARCHAR(24) NULL;
ALTER TABLE pull_request_bypass_requests ADD COLUMN reason_code VARCHAR(24) NULL;

CREATE TABLE bypass_finding_identity (
 bypass_id BIGINT NOT NULL, finding_id BIGINT NOT NULL, rule_id BIGINT NULL,
 revision VARCHAR(64) NULL, effective_blocking BOOLEAN NULL,
 PRIMARY KEY(bypass_id,finding_id), INDEX idx_bypass_rule (rule_id,revision)
);
