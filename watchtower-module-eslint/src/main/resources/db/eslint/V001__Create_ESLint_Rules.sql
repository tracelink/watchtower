CREATE TABLE eslint_rules (
  rule_id BIGINT NOT NULL,
  core BOOLEAN NOT NULL,
  create_function BLOB NULL,
  rule_type varchar(255) NULL,
  category varchar(255) NULL,
  recommended BOOLEAN NULL,
  suggestion BOOLEAN NULL,
  fixable varchar(255) NULL,
  rule_schema BLOB NULL,
  deprecated BOOLEAN NULL,
  replaced_by BLOB NULL,
  PRIMARY KEY (rule_id),
  CONSTRAINT fk_pk_eslint_rule FOREIGN KEY (rule_id) REFERENCES rules (rule_id)
);

CREATE TABLE eslint_messages (
  message_id BIGINT NOT NULL AUTO_INCREMENT,
  rule_id BIGINT NOT NULL,
  message_key varchar(255) NOT NULL,
  message_value varchar(255) NOT NULL,
  PRIMARY KEY (message_id),
  CONSTRAINT fk_property_eslint_rule FOREIGN KEY (rule_id) REFERENCES eslint_rules (rule_id)
);
