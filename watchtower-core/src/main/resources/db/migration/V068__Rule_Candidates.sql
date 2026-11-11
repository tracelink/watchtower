-- Definitions contain authored rule configuration only; fixture assets stay in a reviewed repository.
ALTER TABLE rules ADD COLUMN definition_version BIGINT NOT NULL DEFAULT 0;
CREATE TABLE rule_definition_versions (
 version_id CHAR(36) NOT NULL PRIMARY KEY, rule_id BIGINT NOT NULL,
 revision CHAR(64) NOT NULL, definition_hash CHAR(64) NOT NULL, module VARCHAR(64) NOT NULL,
 definition_json LONGTEXT NOT NULL, actor VARCHAR(255) NOT NULL, created_at BIGINT NOT NULL,
 UNIQUE KEY uq_definition_version (rule_id, definition_hash), INDEX idx_definition_rule (rule_id, created_at)
);
CREATE TABLE rule_candidates (
 candidate_id CHAR(36) NOT NULL PRIMARY KEY, rule_id BIGINT NOT NULL,
 base_revision CHAR(64) NOT NULL, base_definition_hash CHAR(64) NOT NULL,
 revision CHAR(64) NOT NULL, definition_json LONGTEXT NOT NULL,
 status VARCHAR(24) NOT NULL, rationale VARCHAR(300) NOT NULL, reviewer VARCHAR(255) NOT NULL,
 review_id CHAR(36) NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, version BIGINT NOT NULL,
 INDEX idx_candidate_rule (rule_id, status, created_at), INDEX idx_candidate_shadow (status, created_at)
);
CREATE TABLE rule_evaluation_fixtures (
 fixture_id CHAR(36) NOT NULL PRIMARY KEY, rule_id BIGINT NOT NULL,
 fixture_ref VARCHAR(255) NOT NULL, fixture_hash CHAR(64) NOT NULL,
 expected_behavior VARCHAR(24) NOT NULL, cohort VARCHAR(24) NOT NULL,
 reviewer VARCHAR(255) NOT NULL, evidence_ref VARCHAR(255) NOT NULL, created_at BIGINT NOT NULL,
 UNIQUE KEY uq_evaluation_fixture (rule_id, fixture_ref, fixture_hash), INDEX idx_fixture_rule (rule_id, cohort)
);
CREATE TABLE rule_candidate_runs (
 run_id CHAR(36) NOT NULL PRIMARY KEY, candidate_id CHAR(36) NOT NULL,
 base_revision CHAR(64) NOT NULL, candidate_revision CHAR(64) NOT NULL,
 evidence_hash CHAR(64) NOT NULL, evidence_json LONGTEXT NOT NULL,
 status VARCHAR(24) NOT NULL, actor VARCHAR(255) NOT NULL, created_at BIGINT NOT NULL,
 active_candidate CHAR(36) NULL, claim_token CHAR(36) NULL, lease_until BIGINT NULL,
 UNIQUE KEY uq_candidate_running (active_candidate), INDEX idx_candidate_run (candidate_id, created_at)
);
CREATE TABLE rule_candidate_actions (
 action_id CHAR(36) NOT NULL PRIMARY KEY, candidate_id CHAR(36) NOT NULL,
 action VARCHAR(24) NOT NULL, revision CHAR(64) NOT NULL, run_id CHAR(36) NULL,
 evidence_hash CHAR(64) NULL, actor VARCHAR(255) NOT NULL, rationale VARCHAR(300) NOT NULL,
 created_at BIGINT NOT NULL, INDEX idx_candidate_action (candidate_id, created_at)
);
CREATE TABLE rule_shadow_observations (
 observation_id CHAR(64) NOT NULL PRIMARY KEY, candidate_id CHAR(36) NOT NULL,
 scan_type VARCHAR(24) NOT NULL, scan_id BIGINT NOT NULL,
 base_revision CHAR(64) NOT NULL, candidate_revision CHAR(64) NOT NULL,
 execution_identity CHAR(64) NOT NULL, status VARCHAR(24) NOT NULL,
 evidence_json LONGTEXT NOT NULL, elapsed_millis BIGINT NOT NULL, created_at BIGINT NOT NULL,
 INDEX idx_shadow_window (candidate_id, created_at)
);
