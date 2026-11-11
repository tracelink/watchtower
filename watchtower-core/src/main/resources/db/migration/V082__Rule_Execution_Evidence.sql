-- Historical per-rule coverage does not establish whether its engine completed.
ALTER TABLE rule_metric_scan ADD COLUMN engine_status VARCHAR(24) NOT NULL DEFAULT 'UNKNOWN';
