ALTER TABLE aws_security_scan_runs ADD COLUMN mapper_version VARCHAR(64);
ALTER TABLE aws_security_scan_runs ADD COLUMN job_receipt_json TEXT;
ALTER TABLE aws_security_scan_runs ADD COLUMN import_attempts INT NOT NULL DEFAULT 0;
ALTER TABLE aws_security_scan_runs ADD COLUMN source_index_key VARCHAR(255);
ALTER TABLE aws_security_scan_runs ADD COLUMN omitted_count INT NOT NULL DEFAULT 0;
ALTER TABLE aws_security_scan_runs ADD COLUMN artifact_pages INT NOT NULL DEFAULT 0;
ALTER TABLE aws_security_scan_runs ADD COLUMN failure_count BIGINT NOT NULL DEFAULT 0;
ALTER TABLE aws_security_scan_runs ADD COLUMN throttle_count BIGINT NOT NULL DEFAULT 0;

CREATE TABLE aws_security_severity_counts (
    run_id VARCHAR(36) NOT NULL, severity VARCHAR(24) NOT NULL, finding_count INT NOT NULL,
    PRIMARY KEY (run_id, severity), CONSTRAINT fk_aws_severity_run FOREIGN KEY (run_id) REFERENCES aws_security_scan_runs(id)
);
CREATE TABLE aws_security_validation_counts (
    run_id VARCHAR(36) NOT NULL, validation VARCHAR(128) NOT NULL, finding_count INT NOT NULL,
    PRIMARY KEY (run_id, validation), CONSTRAINT fk_aws_validation_run FOREIGN KEY (run_id) REFERENCES aws_security_scan_runs(id)
);
