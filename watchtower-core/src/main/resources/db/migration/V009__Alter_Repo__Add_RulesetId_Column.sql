ALTER TABLE repositories ADD ruleset_id BIGINT;
ALTER TABLE repositories ADD CONSTRAINT fk_repo_rulesetid FOREIGN KEY (ruleset_id) REFERENCES rulesets (ruleset_id);
