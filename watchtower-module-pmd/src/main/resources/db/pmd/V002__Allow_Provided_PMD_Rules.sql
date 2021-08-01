ALTER TABLE pmd_rules DROP description;
ALTER TABLE pmd_rules ADD provided boolean NOT NULL;
ALTER TABLE pmd_rules MODIFY parser_language varchar(255) DEFAULT NULL;
ALTER TABLE pmd_rules MODIFY rule_class varchar(255) DEFAULT NULL;
