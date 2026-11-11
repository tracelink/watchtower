-- A first version of this migration failed on MySQL after creating the table (its index was
-- too long; MySQL DDL is not transactional). The table is new in this migration, so dropping it
-- here can only remove that empty leftover, and a retry no longer trips over it.
DROP TABLE IF EXISTS pull_request_bypass_requests;

-- A developer's request that a privileged user bypass Watchtower's blocking of their pull
-- request (§4.17). Approving it performs a normal bypass (pull_request_bypasses); the request
-- row stays for the audit trail.
CREATE TABLE pull_request_bypass_requests (
  request_id BIGINT NOT NULL AUTO_INCREMENT,
  api_label VARCHAR(255) NOT NULL,
  repo_name VARCHAR(255) NOT NULL,
  pr_id VARCHAR(255) NOT NULL,
  scan_id BIGINT NOT NULL,
  requested_by VARCHAR(255) NOT NULL,
  reason VARCHAR(1000) NOT NULL,
  created_at BIGINT NOT NULL,
  status VARCHAR(16) NOT NULL,
  decided_by VARCHAR(255) NULL,
  decided_at BIGINT NULL,
  decision_note VARCHAR(1000) NULL,
  -- SHA-256 of the pull request while the request is PENDING, NULL once decided: the unique
  -- index then allows only one pending request per pull request (MySQL allows many NULLs).
  pending_key CHAR(64) NULL,
  PRIMARY KEY (request_id)
);

-- Not (…, status): three VARCHAR(255) columns are 3060 bytes in utf8mb4, and InnoDB keys are
-- capped at 3072 bytes, so a fourth column fails on MySQL (H2 does not enforce the cap).
CREATE INDEX idx_pr_bypass_request_pr
  ON pull_request_bypass_requests (api_label, repo_name, pr_id);

CREATE UNIQUE INDEX uq_pr_bypass_request_pending
  ON pull_request_bypass_requests (pending_key);
