CREATE TABLE rule_review_items (
 review_id CHAR(36) NOT NULL PRIMARY KEY, rule_id BIGINT NOT NULL, revision VARCHAR(64) NULL,
 owner VARCHAR(255) NOT NULL, status VARCHAR(24) NOT NULL, reason VARCHAR(64) NOT NULL,
 recommendation VARCHAR(300) NOT NULL, evidence_type VARCHAR(24) NULL, evidence_id VARCHAR(64) NULL,
 session_id CHAR(36) NULL, turn_id CHAR(36) NULL, outcome VARCHAR(300) NOT NULL,
 created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, version BIGINT NOT NULL,
 INDEX idx_reviews_rule (rule_id, updated_at)
);
CREATE TABLE rule_review_audit (audit_id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
 review_id CHAR(36) NOT NULL, status VARCHAR(24) NOT NULL, actor VARCHAR(255) NOT NULL,
 outcome VARCHAR(300) NOT NULL, changed_at BIGINT NOT NULL, INDEX idx_review_audit (review_id, changed_at));
CREATE TABLE rule_regression_cases (case_id CHAR(36) NOT NULL PRIMARY KEY, rule_id BIGINT NOT NULL,
 revision VARCHAR(64) NULL, case_kind VARCHAR(24) NOT NULL, fixture_ref VARCHAR(255) NOT NULL,
 fixture_hash CHAR(64) NOT NULL, expected_behavior VARCHAR(24) NOT NULL,
 engine VARCHAR(64) NOT NULL, language VARCHAR(64) NOT NULL,
 reviewer VARCHAR(255) NOT NULL, created_at BIGINT NOT NULL, INDEX idx_cases_rule (rule_id, revision));

CREATE TABLE rule_health (
 rule_id BIGINT NOT NULL, revision_key VARCHAR(64) NOT NULL, computed_at BIGINT NOT NULL,
 evidence_json TEXT NOT NULL, PRIMARY KEY(rule_id,revision_key)
);
