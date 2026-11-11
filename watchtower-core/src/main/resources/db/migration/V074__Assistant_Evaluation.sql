-- Step 13 activation gate: engineer-reviewed answer evaluation through the real chat pipeline.
-- Only checks, scores and turn references are stored; answers stay in expiring transcripts.
CREATE TABLE assistant_evaluation_runs (
 run_id CHAR(36) NOT NULL PRIMARY KEY,
 cases_version VARCHAR(32) NOT NULL,
 requested_by VARCHAR(255) NOT NULL,
 model VARCHAR(128) NOT NULL,
 effort VARCHAR(24) NOT NULL,
 status VARCHAR(16) NOT NULL,
 case_count INT NOT NULL,
 created_at BIGINT NOT NULL,
 updated_at BIGINT NOT NULL,
 finished_at BIGINT NULL,
 INDEX idx_assistant_evaluation_created (created_at)
);

CREATE TABLE assistant_evaluation_results (
 result_id CHAR(36) NOT NULL PRIMARY KEY,
 run_id CHAR(36) NOT NULL,
 position INT NOT NULL,
 case_id VARCHAR(64) NOT NULL,
 category VARCHAR(32) NOT NULL,
 prompt_hash CHAR(64) NOT NULL,
 -- The exact question and checks, expanded from the installation's own rule ids/names (no source).
 spec_json TEXT NOT NULL,
 session_id CHAR(36) NULL,
 turn_id CHAR(36) NULL,
 status VARCHAR(16) NOT NULL,
 error_code VARCHAR(64) NULL,
 checks_json TEXT NULL,
 auto_passed BOOLEAN NULL,
 tokens BIGINT NOT NULL DEFAULT 0,
 cost_micros BIGINT NOT NULL DEFAULT 0,
 latency_ms BIGINT NULL,
 score INT NULL,
 reviewer VARCHAR(255) NULL,
 note VARCHAR(300) NULL,
 scored_at BIGINT NULL,
 version BIGINT NOT NULL DEFAULT 0,
 UNIQUE KEY idx_assistant_evaluation_position (run_id, position)
);

INSERT INTO application_persistence_locks(lock_name) VALUES ('assistant-evaluation');
