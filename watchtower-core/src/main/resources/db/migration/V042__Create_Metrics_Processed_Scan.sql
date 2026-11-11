CREATE TABLE metrics_processed_scan (
	scan_type varchar(32) NOT NULL,
	scan_id BIGINT NOT NULL,
	metric_kind varchar(32) NOT NULL,
	PRIMARY KEY (scan_type, scan_id, metric_kind)
);
