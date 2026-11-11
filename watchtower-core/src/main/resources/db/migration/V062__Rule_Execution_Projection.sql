-- Immutable, source-free per-scan contributions permit idempotent reconciliation.
CREATE TABLE rule_metric_scan (
 scan_type VARCHAR(24) NOT NULL, scan_id BIGINT NOT NULL, identity_key CHAR(64) NOT NULL,
 rule_id BIGINT NULL, revision VARCHAR(64) NULL, module VARCHAR(64) NULL,
 bucket_start BIGINT NOT NULL, findings BIGINT NOT NULL, blocking BIGINT NOT NULL,
 blocking_unknown BIGINT NOT NULL, opportunities BIGINT NULL,
 coverage VARCHAR(24) NOT NULL, last_fired BIGINT NULL,
 PRIMARY KEY (scan_type, scan_id, identity_key),
 INDEX idx_rule_metric_window (rule_id, revision, bucket_start)
);
CREATE TABLE rule_metric_daily (
 scan_type VARCHAR(24) NOT NULL, bucket_start BIGINT NOT NULL, identity_key CHAR(64) NOT NULL,
 rule_id BIGINT NULL, revision VARCHAR(64) NULL, findings BIGINT NOT NULL,
 blocking BIGINT NOT NULL, blocking_unknown BIGINT NOT NULL, scans BIGINT NOT NULL,
 PRIMARY KEY (scan_type, bucket_start, identity_key), INDEX idx_rule_daily (rule_id, revision, bucket_start)
);
CREATE TABLE rule_metric_processed (scan_type VARCHAR(24) NOT NULL, scan_id BIGINT NOT NULL,
 PRIMARY KEY (scan_type, scan_id));
