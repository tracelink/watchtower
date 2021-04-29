CREATE TABLE regex_rules (
  rule_id BIGINT NOT NULL,
  file_extension varchar(255) DEFAULT '',
  regex_pattern BLOB NOT NULL,
  PRIMARY KEY (rule_id),
  CONSTRAINT fk_pk_regex_rule FOREIGN KEY (rule_id) REFERENCES rules (rule_id)
);