-- Per-scan timings power the user-visible total and the administrator phase breakdown.
-- Defaults keep historical rows readable while distinguishing them as not measured.
ALTER TABLE pull_request_scans ADD COLUMN total_duration_ms BIGINT NOT NULL DEFAULT 0;
ALTER TABLE pull_request_scans ADD COLUMN queue_wait_duration_ms BIGINT NOT NULL DEFAULT 0;
ALTER TABLE pull_request_scans ADD COLUMN source_preparation_duration_ms BIGINT NOT NULL DEFAULT 0;
ALTER TABLE pull_request_scans ADD COLUMN scanner_execution_duration_ms BIGINT NOT NULL DEFAULT 0;
ALTER TABLE pull_request_scans ADD COLUMN result_processing_duration_ms BIGINT NOT NULL DEFAULT 0;
ALTER TABLE pull_request_scans ADD COLUMN scm_reporting_duration_ms BIGINT NOT NULL DEFAULT 0;
ALTER TABLE pull_request_scans ADD COLUMN persistence_duration_ms BIGINT NOT NULL DEFAULT 0;
ALTER TABLE pull_request_scans ADD COLUMN cleanup_duration_ms BIGINT NOT NULL DEFAULT 0;
ALTER TABLE pull_request_scans ADD COLUMN performance_complete BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE pull_request_scans ADD COLUMN changed_file_count INT NOT NULL DEFAULT 0;
ALTER TABLE pull_request_scans ADD COLUMN scan_scope VARCHAR(32) DEFAULT NULL;
ALTER TABLE pull_request_scans ADD COLUMN source_strategy VARCHAR(64) DEFAULT NULL;
ALTER TABLE pull_request_scans ADD COLUMN scanner_timings_json TEXT DEFAULT NULL;

ALTER TABLE pull_request_sync_settings
    ADD COLUMN performance_window_days INT NOT NULL DEFAULT 7;
