CREATE TABLE betterleaks_rules (
  rule_id BIGINT NOT NULL,
  provided BOOLEAN NOT NULL,
  betterleaks_id VARCHAR(100) NOT NULL,
  category VARCHAR(32) NOT NULL,
  confidence VARCHAR(16) NULL,
  PRIMARY KEY (rule_id),
  CONSTRAINT fk_pk_betterleaks_rule FOREIGN KEY (rule_id) REFERENCES rules (rule_id)
);
