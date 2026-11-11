-- Unknown historical dates, provenance and executable revisions deliberately stay NULL.
-- These columns contain metadata only; module definitions remain in their own histories.
ALTER TABLE rules ADD COLUMN rule_state VARCHAR(16) NOT NULL DEFAULT 'ACTIVE';
ALTER TABLE rules ADD COLUMN rule_owner VARCHAR(255) NULL;
ALTER TABLE rules ADD COLUMN review_by DATE NULL;
ALTER TABLE rules ADD COLUMN cwe VARCHAR(32) NULL;
ALTER TABLE rules ADD COLUMN stewardship_category VARCHAR(128) NULL;
ALTER TABLE rules ADD COLUMN origin VARCHAR(255) NULL;
ALTER TABLE rules ADD COLUMN origin_key VARCHAR(255) NULL;
ALTER TABLE rules ADD COLUMN rule_revision CHAR(64) NULL;
ALTER TABLE rules ADD COLUMN created_at BIGINT NULL;
ALTER TABLE rules ADD COLUMN updated_at BIGINT NULL;
CREATE INDEX idx_rules_state_review ON rules (rule_state, review_by);

-- Keep the actor and metadata history even if an explicitly deleted custom rule disappears.
CREATE TABLE rule_stewardship_history (
  history_id BIGINT NOT NULL AUTO_INCREMENT,
  rule_id BIGINT NOT NULL,
  changed_by VARCHAR(255) NOT NULL,
  changed_at BIGINT NOT NULL,
  rule_state VARCHAR(16) NOT NULL,
  rule_owner VARCHAR(255) NULL,
  review_by DATE NULL,
  cwe VARCHAR(32) NULL,
  stewardship_category VARCHAR(128) NULL,
  origin VARCHAR(255) NULL,
  origin_key VARCHAR(255) NULL,
  rule_revision CHAR(64) NULL,
  created_at BIGINT NULL,
  updated_at BIGINT NULL,
  PRIMARY KEY (history_id)
);
CREATE INDEX idx_rule_stewardship_history ON rule_stewardship_history (rule_id, changed_at, history_id);
