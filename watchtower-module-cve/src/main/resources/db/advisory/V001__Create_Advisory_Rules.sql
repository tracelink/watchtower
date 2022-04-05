CREATE TABLE advisory_rules (
  rule_id BIGINT NOT NULL,
  advisory_type varchar(15) NOT NULL,
  package_name varchar(255) NOT NULL,
  score varchar(15) NOT NULL,
  vector varchar(255) NOT NULL,
  PRIMARY KEY (rule_id),
  CONSTRAINT fk_pk_advisory_rule FOREIGN KEY (rule_id) REFERENCES rules (rule_id)
);