-- Whether a scan blocked its pull request (new findings at or above the ruleset's blocking
-- level, after any bypass). The per-violation flags are not persisted, so the report page needs
-- this to know when "Bypass blocking" applies.
ALTER TABLE pull_request_scans ADD COLUMN blocked BOOLEAN NOT NULL DEFAULT FALSE;

-- A privileged user's decision to stop Watchtower blocking one pull request, for the findings
-- present at the time. Revoking keeps the row for the audit trail.
CREATE TABLE pull_request_bypasses (
  bypass_id BIGINT NOT NULL AUTO_INCREMENT,
  api_label VARCHAR(255) NOT NULL,
  repo_name VARCHAR(255) NOT NULL,
  pr_id VARCHAR(255) NOT NULL,
  scan_id BIGINT NOT NULL,
  commit_hash VARCHAR(64) NULL,
  bypassed_by VARCHAR(255) NOT NULL,
  reason VARCHAR(1000) NOT NULL,
  created_at BIGINT NOT NULL,
  revoked_by VARCHAR(255) NULL,
  revoked_at BIGINT NULL,
  PRIMARY KEY (bypass_id)
);

CREATE INDEX idx_pr_bypass_pr ON pull_request_bypasses (api_label, repo_name, pr_id);

-- The findings a bypass covers, by rule and file: a new blocking finding of another rule, or in
-- another file, still blocks.
CREATE TABLE pull_request_bypass_findings (
  bypass_id BIGINT NOT NULL,
  rule_name VARCHAR(255) NOT NULL,
  file_path VARCHAR(1024) NOT NULL,
  CONSTRAINT fk_pr_bypass_finding FOREIGN KEY (bypass_id) REFERENCES pull_request_bypasses (bypass_id)
);
