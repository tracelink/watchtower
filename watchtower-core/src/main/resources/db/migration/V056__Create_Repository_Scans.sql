/*
 * Repository Scan (docs/repository-scan.plan.md §1).
 *
 * repositories becomes the persisted repository catalog: a sync from each SCM integration
 * inserts every repository it lists, not only those that have had a pull request. A synced
 * repository that has never had a pull request keeps last_review_date = 0.
 * Findings are not stored here: each scan's findings are a JSON object in S3 (no source code);
 * repo_scans keeps only the summary that lists and dashboards need.
 */

ALTER TABLE repositories ADD COLUMN project_key VARCHAR(64);
ALTER TABLE repositories ADD COLUMN default_branch VARCHAR(255);
ALTER TABLE repositories ADD COLUMN last_commit_at BIGINT;
ALTER TABLE repositories ADD COLUMN size_bytes BIGINT;
ALTER TABLE repositories ADD COLUMN primary_language VARCHAR(64);
ALTER TABLE repositories ADD COLUMN scm_synced_at BIGINT;
ALTER TABLE repositories ADD COLUMN team VARCHAR(128);
ALTER TABLE repositories ADD COLUMN owner_name VARCHAR(255);
ALTER TABLE repositories ADD COLUMN labels VARCHAR(512);
ALTER TABLE repositories ADD COLUMN criticality TINYINT NOT NULL DEFAULT 3;
ALTER TABLE repositories ADD COLUMN last_repo_scan_id BIGINT;

-- One row per repository of an integration. Also indexes the lookup every PR webhook makes.
-- 2 x 255 utf8mb4 chars = 2040 bytes, under MySQL's 3072-byte key limit.
CREATE UNIQUE INDEX uq_repositories_label_name ON repositories (api_label, repo_name);

CREATE TABLE repo_scan_plans (
	plan_id BIGINT NOT NULL AUTO_INCREMENT,
	name VARCHAR(255) NOT NULL,
	api_label VARCHAR(255) NOT NULL,
	repo_selector TEXT NOT NULL,
	branch_selector VARCHAR(512),
	ruleset_id BIGINT,
	frequency VARCHAR(16) NOT NULL,
	schedule_hour TINYINT,
	schedule_day TINYINT,
	skip_stale_days INT,
	next_run_at BIGINT,
	last_run_at BIGINT,
	run_count INT NOT NULL DEFAULT 0,
	enabled BOOLEAN NOT NULL DEFAULT TRUE,
	created_by VARCHAR(255) NOT NULL,
	created_at BIGINT NOT NULL,
	PRIMARY KEY (plan_id),
	CONSTRAINT fk_repo_scan_plans_ruleset FOREIGN KEY (ruleset_id)
		REFERENCES rulesets (ruleset_id) ON DELETE SET NULL
);

CREATE INDEX idx_repo_scan_plans_due ON repo_scan_plans (enabled, next_run_at);

CREATE TABLE repo_scans (
	scan_id BIGINT NOT NULL AUTO_INCREMENT,
	plan_id BIGINT NOT NULL,
	run_no INT NOT NULL,
	repo_entity_id BIGINT NOT NULL,
	branch VARCHAR(255) NOT NULL,
	commit_hash VARCHAR(64),
	commit_date BIGINT,
	ruleset_name VARCHAR(255),
	ruleset_fingerprint VARCHAR(32),
	status VARCHAR(32) NOT NULL,
	outcome VARCHAR(16),
	priority TINYINT NOT NULL DEFAULT 3,
	submit_date BIGINT NOT NULL,
	start_date BIGINT,
	end_date BIGINT,
	attempts TINYINT NOT NULL DEFAULT 0,
	worker_id VARCHAR(64),
	heartbeat_at BIGINT,
	error VARCHAR(1024),
	finding_count INT NOT NULL DEFAULT 0,
	max_severity TINYINT,
	severity_counts VARCHAR(64),
	rule_counts TEXT,
	new_count INT,
	fixed_count INT,
	report_key VARCHAR(512),
	rules_evaluated INT,
	scanner_executions_json TEXT,
	PRIMARY KEY (scan_id),
	CONSTRAINT fk_repo_scans_plan FOREIGN KEY (plan_id)
		REFERENCES repo_scan_plans (plan_id) ON DELETE CASCADE,
	CONSTRAINT fk_repo_scans_repo FOREIGN KEY (repo_entity_id)
		REFERENCES repositories (repo_entity_id)
);

CREATE INDEX idx_repo_scans_run ON repo_scans (plan_id, run_no);
CREATE INDEX idx_repo_scans_repo_branch ON repo_scans (repo_entity_id, branch, end_date);
CREATE INDEX idx_repo_scans_status ON repo_scans (status, submit_date);

-- Background work other than scans (catalog sync, plan expansion, exports), for queue
-- visibility. dedup_key is set only while a job is queued or running, so a second identical
-- job is refused until the first finishes.
CREATE TABLE async_jobs (
	job_id BIGINT NOT NULL AUTO_INCREMENT,
	job_type VARCHAR(32) NOT NULL,
	status VARCHAR(16) NOT NULL,
	dedup_key VARCHAR(128),
	payload VARCHAR(1024),
	progress VARCHAR(255),
	result_key VARCHAR(512),
	error VARCHAR(1024),
	created_by VARCHAR(255),
	created_at BIGINT NOT NULL,
	started_at BIGINT,
	finished_at BIGINT,
	heartbeat_at BIGINT,
	PRIMARY KEY (job_id),
	CONSTRAINT uq_async_jobs_dedup UNIQUE (dedup_key)
);

CREATE INDEX idx_async_jobs_status ON async_jobs (status, created_at);

-- One row: settings that every pod must agree on.
CREATE TABLE repo_scan_settings (
	settings_id BIGINT NOT NULL,
	paused BOOLEAN NOT NULL DEFAULT FALSE,
	sync_frequency_hours INT NOT NULL DEFAULT 6,
	last_sync_at BIGINT,
	PRIMARY KEY (settings_id)
);

INSERT INTO repo_scan_settings (settings_id, paused, sync_frequency_hours) VALUES (1, FALSE, 6);
