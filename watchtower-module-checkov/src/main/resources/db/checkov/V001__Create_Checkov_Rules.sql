CREATE TABLE checkov_rules (
  rule_id BIGINT NOT NULL,
  core BOOLEAN NOT NULL,
  code BLOB NULL,
  checkovtype varchar(255) NULL,
  entity varchar(255) NULL,
  iac varchar(255) NULL,
  PRIMARY KEY (rule_id),
  CONSTRAINT fk_pk_checkov_rule FOREIGN KEY (rule_id) REFERENCES rules (rule_id)
);
