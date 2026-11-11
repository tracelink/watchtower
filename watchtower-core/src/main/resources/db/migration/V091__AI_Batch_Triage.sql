-- Batch triage: advice on up to 40 findings of one scan, run as a background job. One run per scan, one
-- item per finding, so a restarted or duplicated job resumes where it stopped. No source code is kept.
CREATE TABLE ai_batch_run (
 run_id CHAR(36) NOT NULL PRIMARY KEY,
 scan_type VARCHAR(16) NOT NULL,
 scan_id BIGINT NOT NULL,
 requested_by VARCHAR(255) NOT NULL,
 status VARCHAR(16) NOT NULL,
 total INT NOT NULL,
 done INT NOT NULL,
 blocked INT NOT NULL,
 created_at BIGINT NOT NULL,
 finished_at BIGINT NULL,
 UNIQUE KEY uk_ai_batch_scan (scan_type, scan_id)
);
CREATE TABLE ai_batch_item (
 run_id CHAR(36) NOT NULL,
 finding_key VARCHAR(64) NOT NULL,
 status VARCHAR(20) NOT NULL,
 assessment_id CHAR(36) NULL,
 PRIMARY KEY (run_id, finding_key)
);
