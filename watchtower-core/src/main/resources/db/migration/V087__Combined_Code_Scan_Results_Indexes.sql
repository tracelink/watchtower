CREATE INDEX idx_repo_scans_end_id ON repo_scans (end_date, scan_id);
CREATE INDEX idx_repo_scans_repo_end_id ON repo_scans (repo_entity_id, end_date, scan_id);
CREATE INDEX idx_pr_scans_end_id ON pull_request_scans (end_date, scan_entity_id);
CREATE INDEX idx_pr_scans_container_end_id ON pull_request_scans (container_id, end_date, scan_entity_id);
