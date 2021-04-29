ALTER TABLE rulesets ADD designation varchar(255) NOT NULL;
UPDATE rulesets SET designation = 'DEFAULT' WHERE name = 'Default';
UPDATE rulesets SET designation = 'PRIMARY' WHERE name <> 'Default';