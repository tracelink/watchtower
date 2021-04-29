CREATE TABLE rules (
    rule_id BIGINT NOT NULL AUTO_INCREMENT,
    author int(11) NOT NULL,
    name varchar(255) NOT NULL,
    message BLOB NOT NULL,
    external_url varchar(255) NOT NULL,
    priority TINYINT NOT NULL,
    PRIMARY KEY (rule_id),
    CONSTRAINT fk_author_rule FOREIGN KEY (author) REFERENCES users (user_id)
);

CREATE TABLE rulesets (
  ruleset_id BIGINT NOT NULL AUTO_INCREMENT,
  name varchar(255) NOT NULL,
  description varchar(255) NOT NULL,
  PRIMARY KEY (ruleset_id)
);

CREATE TABLE ruleset_ruleset (
  ruleset_id BIGINT NOT NULL,
  inherited_ruleset_id BIGINT NOT NULL,
  PRIMARY KEY (ruleset_id,inherited_ruleset_id),
  CONSTRAINT fk_ruleset_ruleset_id FOREIGN KEY (ruleset_id) REFERENCES rulesets (ruleset_id),
  CONSTRAINT fk_ruleset_ruleset_inheritedid FOREIGN KEY (inherited_ruleset_id) REFERENCES rulesets (ruleset_id)
);

CREATE TABLE rule_ruleset (
  ruleset_id BIGINT NOT NULL,
  rule_id BIGINT NOT NULL,
  PRIMARY KEY (ruleset_id,rule_id),
  CONSTRAINT fk_rule_ruleset_rulesetid FOREIGN KEY (ruleset_id) REFERENCES rulesets (ruleset_id),
  CONSTRAINT fk_rule_ruleset_ruleid FOREIGN KEY (rule_id) REFERENCES rules (rule_id)
);