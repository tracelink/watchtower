ALTER TABLE pull_request_scans ADD COLUMN rules_evaluated INT DEFAULT NULL;
ALTER TABLE pull_request_scans ADD COLUMN scanner_executions_json TEXT DEFAULT NULL;

ALTER TABLE upload_scans ADD COLUMN rules_evaluated INT DEFAULT NULL;
ALTER TABLE upload_scans ADD COLUMN scanner_executions_json TEXT DEFAULT NULL;

ALTER TABLE image_scan ADD COLUMN rules_evaluated INT DEFAULT NULL;
ALTER TABLE image_scan ADD COLUMN scanner_executions_json TEXT DEFAULT NULL;
