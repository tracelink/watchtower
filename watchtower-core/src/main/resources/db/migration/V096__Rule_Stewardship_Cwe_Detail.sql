-- A rule keeps one primary CWE (cwe) and may list secondary ones; a style or quality rule can be marked
-- as not a security rule so it stops counting as a CWE gap. The history table gets the same columns
-- because it snapshots the same embedded stewardship (see V084 for what happens when it does not).
ALTER TABLE rules ADD COLUMN secondary_cwes VARCHAR(160) NULL;
ALTER TABLE rules ADD COLUMN security_relevance VARCHAR(16) NULL;
ALTER TABLE rule_stewardship_history ADD COLUMN secondary_cwes VARCHAR(160) NULL;
ALTER TABLE rule_stewardship_history ADD COLUMN security_relevance VARCHAR(16) NULL;
