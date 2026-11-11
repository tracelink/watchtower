INSERT INTO metrics_processed_scan (scan_type, scan_id, metric_kind)
	SELECT 'pull_request', scan_entity_id, 'result' FROM pull_request_scans WHERE end_date > 0;
INSERT INTO metrics_processed_scan (scan_type, scan_id, metric_kind)
	SELECT 'pull_request', scan_entity_id, 'performance' FROM pull_request_scans
	WHERE end_date > 0 AND performance_complete = TRUE;
INSERT INTO metrics_processed_scan (scan_type, scan_id, metric_kind)
	SELECT 'upload', scan_entity_id, 'result' FROM upload_scans WHERE end_date > 0;
INSERT INTO metrics_processed_scan (scan_type, scan_id, metric_kind)
	SELECT 'container', scan_entity_id, 'result' FROM image_scan WHERE end_date > 0;
