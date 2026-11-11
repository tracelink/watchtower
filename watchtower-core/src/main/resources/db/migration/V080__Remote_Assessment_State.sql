ALTER TABLE pull_request_scans ADD COLUMN remote_assessment_state VARCHAR(32);
ALTER TABLE pull_request_scans ADD COLUMN remote_completed_at BIGINT;
