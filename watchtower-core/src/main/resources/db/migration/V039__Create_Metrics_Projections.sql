CREATE TABLE metrics_scan_daily (
	scan_type varchar(32) NOT NULL,
	bucket_start BIGINT NOT NULL,
	scan_count BIGINT NOT NULL DEFAULT 0,
	violation_count BIGINT NOT NULL DEFAULT 0,
	duration_sum_ms BIGINT NOT NULL DEFAULT 0,
	duration_count BIGINT NOT NULL DEFAULT 0,
	source_size_sum_bytes BIGINT NOT NULL DEFAULT 0,
	source_size_count BIGINT NOT NULL DEFAULT 0,
	total_duration_sum_ms BIGINT NOT NULL DEFAULT 0,
	queue_duration_sum_ms BIGINT NOT NULL DEFAULT 0,
	source_duration_sum_ms BIGINT NOT NULL DEFAULT 0,
	scanner_duration_sum_ms BIGINT NOT NULL DEFAULT 0,
	processing_duration_sum_ms BIGINT NOT NULL DEFAULT 0,
	scm_duration_sum_ms BIGINT NOT NULL DEFAULT 0,
	persistence_duration_sum_ms BIGINT NOT NULL DEFAULT 0,
	cleanup_duration_sum_ms BIGINT NOT NULL DEFAULT 0,
	performance_count BIGINT NOT NULL DEFAULT 0,
	PRIMARY KEY (scan_type, bucket_start)
);

CREATE INDEX idx_metrics_scan_daily_bucket ON metrics_scan_daily (bucket_start);

CREATE TABLE metrics_violation_daily (
	scan_type varchar(32) NOT NULL,
	bucket_start BIGINT NOT NULL,
	violation_name varchar(255) NOT NULL,
	violation_count BIGINT NOT NULL DEFAULT 0,
	PRIMARY KEY (scan_type, bucket_start, violation_name)
);

CREATE INDEX idx_metrics_violation_daily_bucket
	ON metrics_violation_daily (bucket_start, scan_type);

CREATE TABLE metrics_dimension_summary (
	metric_key varchar(64) NOT NULL,
	metric_value BIGINT NOT NULL DEFAULT 0,
	PRIMARY KEY (metric_key)
);
