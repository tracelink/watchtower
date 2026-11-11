-- RuleRepository.findByName(String) is a derived query on rules.name with no supporting
-- index, so every lookup is a full table scan. A miss (e.g. a Regex/MCR-scanner finding
-- name with no backing RuleEntity row) must scan every row to conclude "no match", which
-- is what made /rest/scan/result/all and /scan/results/all time out - see
-- PRScanResultService.generateResultForViolation.
--
-- Non-unique on purpose: nothing in this codebase enforces rule names are unique, so a
-- UNIQUE index here could fail to apply against existing duplicate data.
CREATE INDEX idx_rules_name ON rules (name);
