ALTER TABLE betterleaks_rules ADD regex VARCHAR(1000) NULL;
ALTER TABLE betterleaks_rules ADD keywords VARCHAR(600) NULL;
ALTER TABLE betterleaks_rules ADD entropy DOUBLE NULL;
ALTER TABLE betterleaks_rules ADD secret_group INT NULL;
ALTER TABLE betterleaks_rules ADD cel_filter VARCHAR(2000) NULL;
ALTER TABLE betterleaks_rules ADD positive_sample TEXT NULL;
ALTER TABLE betterleaks_rules ADD negative_sample TEXT NULL;
ALTER TABLE betterleaks_rules ADD rule_version INT NULL;

CREATE TABLE betterleaks_rule_versions (
  version_id BIGINT NOT NULL AUTO_INCREMENT,
  rule_id BIGINT NOT NULL,
  rule_version INT NOT NULL,
  definition TEXT NOT NULL,
  author VARCHAR(255) NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (version_id),
  CONSTRAINT fk_betterleaks_rule_version FOREIGN KEY (rule_id) REFERENCES betterleaks_rules (rule_id)
);
