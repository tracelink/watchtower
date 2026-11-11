INSERT INTO metrics_scan_daily (
	scan_type, bucket_start, scan_count, violation_count, duration_sum_ms, duration_count,
	source_size_sum_bytes, source_size_count, total_duration_sum_ms,
	queue_duration_sum_ms, source_duration_sum_ms, scanner_duration_sum_ms,
	processing_duration_sum_ms, scm_duration_sum_ms, persistence_duration_sum_ms,
	cleanup_duration_sum_ms, performance_count)
SELECT 'pull_request', FLOOR((s.end_date + ${metricsZoneOffsetMillis}) / 86400000) * 86400000 - ${metricsZoneOffsetMillis}, COUNT(*),
	COALESCE(SUM((SELECT COUNT(*) FROM pull_request_violations v
		WHERE v.scan_entity_id = s.scan_entity_id AND v.severity <> 'Informational')), 0),
	SUM(s.end_date - s.start_date), COUNT(*),
	SUM(CASE WHEN s.source_size_bytes > 0 THEN s.source_size_bytes ELSE 0 END),
	SUM(CASE WHEN s.source_size_bytes > 0 THEN 1 ELSE 0 END),
	SUM(CASE WHEN s.performance_complete = TRUE THEN s.total_duration_ms ELSE 0 END),
	SUM(CASE WHEN s.performance_complete = TRUE THEN s.queue_wait_duration_ms ELSE 0 END),
	SUM(CASE WHEN s.performance_complete = TRUE THEN s.source_preparation_duration_ms ELSE 0 END),
	SUM(CASE WHEN s.performance_complete = TRUE THEN s.scanner_execution_duration_ms ELSE 0 END),
	SUM(CASE WHEN s.performance_complete = TRUE THEN s.result_processing_duration_ms ELSE 0 END),
	SUM(CASE WHEN s.performance_complete = TRUE THEN s.scm_reporting_duration_ms ELSE 0 END),
	SUM(CASE WHEN s.performance_complete = TRUE THEN s.persistence_duration_ms ELSE 0 END),
	SUM(CASE WHEN s.performance_complete = TRUE THEN s.cleanup_duration_ms ELSE 0 END),
	SUM(CASE WHEN s.performance_complete = TRUE THEN 1 ELSE 0 END)
FROM pull_request_scans s WHERE s.end_date > 0
GROUP BY FLOOR((s.end_date + ${metricsZoneOffsetMillis}) / 86400000) * 86400000 - ${metricsZoneOffsetMillis};

INSERT INTO metrics_scan_daily (
	scan_type, bucket_start, scan_count, violation_count, duration_sum_ms, duration_count)
SELECT 'upload', FLOOR((s.end_date + ${metricsZoneOffsetMillis}) / 86400000) * 86400000 - ${metricsZoneOffsetMillis}, COUNT(*),
	COALESCE(SUM((SELECT COUNT(*) FROM upload_violations v
		WHERE v.scan_entity_id = s.scan_entity_id AND v.severity <> 'Informational')), 0),
	SUM(s.end_date - s.start_date), COUNT(*)
FROM upload_scans s WHERE s.end_date > 0
GROUP BY FLOOR((s.end_date + ${metricsZoneOffsetMillis}) / 86400000) * 86400000 - ${metricsZoneOffsetMillis};

INSERT INTO metrics_scan_daily (
	scan_type, bucket_start, scan_count, violation_count, duration_sum_ms, duration_count)
SELECT 'container', FLOOR((s.end_date + ${metricsZoneOffsetMillis}) / 86400000) * 86400000 - ${metricsZoneOffsetMillis}, COUNT(*),
	COALESCE(SUM((SELECT COUNT(*) FROM image_violation v
		WHERE v.scan_entity_id = s.scan_entity_id AND v.severity <> 'Informational')), 0),
	SUM(s.end_date - s.start_date), COUNT(*)
FROM image_scan s WHERE s.end_date > 0
GROUP BY FLOOR((s.end_date + ${metricsZoneOffsetMillis}) / 86400000) * 86400000 - ${metricsZoneOffsetMillis};

INSERT INTO metrics_violation_daily (scan_type, bucket_start, violation_name, violation_count)
SELECT 'pull_request', FLOOR((s.end_date + ${metricsZoneOffsetMillis}) / 86400000) * 86400000 - ${metricsZoneOffsetMillis},
	v.violation_name, COUNT(*)
FROM pull_request_scans s JOIN pull_request_violations v
	ON v.scan_entity_id = s.scan_entity_id
WHERE s.end_date > 0 AND v.severity <> 'Informational'
GROUP BY FLOOR((s.end_date + ${metricsZoneOffsetMillis}) / 86400000) * 86400000 - ${metricsZoneOffsetMillis}, v.violation_name;

INSERT INTO metrics_violation_daily (scan_type, bucket_start, violation_name, violation_count)
SELECT 'upload', FLOOR((s.end_date + ${metricsZoneOffsetMillis}) / 86400000) * 86400000 - ${metricsZoneOffsetMillis},
	v.violation_name, COUNT(*)
FROM upload_scans s JOIN upload_violations v ON v.scan_entity_id = s.scan_entity_id
WHERE s.end_date > 0 AND v.severity <> 'Informational'
GROUP BY FLOOR((s.end_date + ${metricsZoneOffsetMillis}) / 86400000) * 86400000 - ${metricsZoneOffsetMillis}, v.violation_name;

INSERT INTO metrics_violation_daily (scan_type, bucket_start, violation_name, violation_count)
SELECT 'container', FLOOR((s.end_date + ${metricsZoneOffsetMillis}) / 86400000) * 86400000 - ${metricsZoneOffsetMillis},
	v.violation_name, COUNT(*)
FROM image_scan s JOIN image_violation v ON v.scan_entity_id = s.scan_entity_id
WHERE s.end_date > 0 AND v.severity <> 'Informational'
GROUP BY FLOOR((s.end_date + ${metricsZoneOffsetMillis}) / 86400000) * 86400000 - ${metricsZoneOffsetMillis}, v.violation_name;

INSERT INTO metrics_dimension_summary (metric_key, metric_value)
	SELECT 'pull_request_count', COUNT(*) FROM pull_request_container;
INSERT INTO metrics_dimension_summary (metric_key, metric_value)
	SELECT 'repository_count', COUNT(*) FROM repositories WHERE scan_type = 'pull_request';
