-- One AWS code review per repository, reused by every scan of it. Each scan points the review at its own source and starts its
-- own job; the lock keeps two scans from interleaving "change the source" and "start the job" (a job records its own source).
CREATE TABLE aws_security_repo_review (
    repository_id BIGINT NOT NULL PRIMARY KEY,
    version BIGINT NOT NULL DEFAULT 0,
    space_id VARCHAR(64) NOT NULL,
    title VARCHAR(100) NOT NULL,
    review_id VARCHAR(128),
    lock_owner VARCHAR(36),
    lock_until BIGINT NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL
);
ALTER TABLE aws_security_scan_runs ADD COLUMN shared_review BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE aws_security_scan_runs ADD COLUMN start_attempt_at BIGINT;
