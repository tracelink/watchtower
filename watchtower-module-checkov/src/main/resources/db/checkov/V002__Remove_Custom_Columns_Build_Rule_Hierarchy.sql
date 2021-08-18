ALTER TABLE checkov_rules DROP core;
ALTER TABLE checkov_rules DROP code;
ALTER TABLE checkov_rules ADD provided boolean;
UPDATE checkov_rules SET provided = true;
ALTER TABLE checkov_rules MODIFY provided boolean NOT NULL;

CREATE TABLE rule_definition(
	definition_id BIGINT NOT NULL AUTO_INCREMENT,
	rule_id BIGINT NOT NULL,
	checkovtype varchar(255) NULL,
	entity varchar(255) NULL,
	iac varchar(255) NULL,
	PRIMARY KEY (definition_id),
	CONSTRAINT fk_definition_checkov_rule FOREIGN KEY (rule_id) REFERENCES checkov_rules (rule_id)
);

INSERT INTO rule_definition(rule_id, checkovtype, entity, iac) 
	SELECT rule_id, checkovtype, entity, iac
		FROM checkov_rules;

ALTER TABLE checkov_rules DROP checkovtype;
ALTER TABLE checkov_rules DROP entity;
ALTER TABLE checkov_rules DROP iac;
