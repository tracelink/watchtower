CREATE TABLE opengrep_rules (
 rule_id BIGINT NOT NULL PRIMARY KEY,
 engine_rule_id VARCHAR(150) NOT NULL,
 definition_json TEXT NOT NULL,
 rule_license VARCHAR(100) NOT NULL,
 rule_source VARCHAR(255) NOT NULL,
 provided BOOLEAN NOT NULL DEFAULT FALSE,
 CONSTRAINT fk_opengrep_rule FOREIGN KEY (rule_id) REFERENCES rules(rule_id)
);
