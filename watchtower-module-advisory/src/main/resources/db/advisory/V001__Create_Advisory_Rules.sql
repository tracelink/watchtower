CREATE TABLE advisory_rules (
  rule_id BIGINT NOT NULL,
  PRIMARY KEY (rule_id),
  CONSTRAINT fk_pk_advisory_rule FOREIGN KEY (rule_id) REFERENCES rules (rule_id)
);