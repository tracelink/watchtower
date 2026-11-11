-- V073 added upstream_hold_since to rules, and RuleStewardshipHistoryEntity snapshots the same
-- embedded stewardship, but the history table never got the column: every owner/CWE save failed
-- with "Unknown column upstream_hold_since". Additive and nullable; old snapshots stay NULL.
ALTER TABLE rule_stewardship_history ADD COLUMN upstream_hold_since BIGINT NULL;
