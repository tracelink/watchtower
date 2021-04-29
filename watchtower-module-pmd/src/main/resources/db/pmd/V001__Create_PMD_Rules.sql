CREATE TABLE pmd_rules (
  rule_id BIGINT NOT NULL,
  parser_language varchar(255) NOT NULL,
  rule_class varchar(255) NOT NULL,
  description BLOB NOT NULL,
  PRIMARY KEY (rule_id),
  CONSTRAINT fk_pk_pmd_rule FOREIGN KEY (rule_id) REFERENCES rules (rule_id)
);

CREATE TABLE pmd_properties (
  property_id BIGINT NOT NULL AUTO_INCREMENT,
  rule_id BIGINT NOT NULL,
  property_name varchar(255) NOT NULL,
  property_value BLOB NOT NULL,
  PRIMARY KEY (property_id),
  CONSTRAINT fk_property_pmd_rule FOREIGN KEY (rule_id) REFERENCES pmd_rules (rule_id)
);