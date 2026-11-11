ALTER TABLE pull_request_scans ADD COLUMN provider_summary_json TEXT;
ALTER TABLE repo_scans ADD COLUMN provider_summary_json TEXT;
