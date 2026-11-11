ALTER TABLE aws_security_scan_runs ADD COLUMN setup_requester VARCHAR(255);
ALTER TABLE aws_security_scan_runs ADD COLUMN setup_mode VARCHAR(24);
ALTER TABLE aws_security_scan_runs ADD COLUMN inputs_verified BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX aws_security_setup_history ON aws_security_scan_runs(parent_type, created_at);
