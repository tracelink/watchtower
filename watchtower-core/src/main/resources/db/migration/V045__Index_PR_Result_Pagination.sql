-- Supports latest-scan-per-container MCR pagination and exact grouped finding counts.
CREATE INDEX idx_pr_scans_container_submit
	ON pull_request_scans (container_id, submit_date);

CREATE INDEX idx_pr_violations_scan_name
	ON pull_request_violations (scan_entity_id, violation_name);
