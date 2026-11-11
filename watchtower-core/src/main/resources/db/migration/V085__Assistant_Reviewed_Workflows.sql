-- Additive configuration concurrency and source-free assistant decisions. Legacy data is not AI-approved.
ALTER TABLE rulesets ADD COLUMN configuration_version BIGINT NOT NULL DEFAULT 0;
ALTER TABLE repositories ADD COLUMN configuration_version BIGINT NOT NULL DEFAULT 0;
INSERT INTO application_persistence_locks (lock_name) VALUES ('ruleset-configuration');
CREATE TABLE assistant_ruleset_change_sets (
 id VARCHAR(36) PRIMARY KEY, owner VARCHAR(255) NOT NULL, request_key VARCHAR(36) NOT NULL,
 turn_id VARCHAR(36), version BIGINT NOT NULL DEFAULT 0, status VARCHAR(20) NOT NULL,
 content_hash VARCHAR(64) NOT NULL, request_hash VARCHAR(64) NOT NULL,
 request_json LONGTEXT NOT NULL, preview_json LONGTEXT NOT NULL,
 created_at BIGINT NOT NULL, expires_at BIGINT NOT NULL,
 CONSTRAINT uq_assistant_ruleset_request UNIQUE (owner, request_key)
);
CREATE INDEX idx_assistant_ruleset_owner ON assistant_ruleset_change_sets (owner, created_at);
CREATE TABLE assistant_ruleset_receipts (
 change_set_id VARCHAR(36) PRIMARY KEY, actor VARCHAR(255) NOT NULL,
 content_hash VARCHAR(64) NOT NULL, applied_at BIGINT NOT NULL, receipt_json LONGTEXT NOT NULL
);
CREATE TABLE rule_improvement_proposals (
 id VARCHAR(36) PRIMARY KEY, version BIGINT NOT NULL DEFAULT 0,
 owner VARCHAR(255) NOT NULL, request_key VARCHAR(36) NOT NULL, rule_id BIGINT NOT NULL,
 base_revision VARCHAR(64), definition_hash VARCHAR(64) NOT NULL,
 evidence_hash VARCHAR(64) NOT NULL, request_hash VARCHAR(64) NOT NULL,
 manifest_json LONGTEXT NOT NULL, turn_id VARCHAR(36), status VARCHAR(24) NOT NULL,
 model VARCHAR(128), effort VARCHAR(16), prompt_version VARCHAR(32) NOT NULL,
 proposal_json LONGTEXT, created_at BIGINT NOT NULL,
 CONSTRAINT uq_rule_improvement_request UNIQUE (owner, request_key)
);
CREATE INDEX idx_rule_improvement_owner ON rule_improvement_proposals (owner, rule_id, created_at);
CREATE TABLE rule_candidate_provenance (
 candidate_id VARCHAR(36) PRIMARY KEY, proposal_id VARCHAR(36) NOT NULL UNIQUE,
 rule_id BIGINT NOT NULL, base_revision VARCHAR(64) NOT NULL, evidence_hash VARCHAR(64) NOT NULL,
 actor VARCHAR(255) NOT NULL, accepted_patch_json LONGTEXT NOT NULL, created_at BIGINT NOT NULL
);
