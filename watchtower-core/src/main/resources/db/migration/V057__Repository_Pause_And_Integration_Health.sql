/*
 * Repositories inventory (docs/repository-scan.plan.md, repositories UX rebuild).
 *
 * Column adds only (MySQL 8.4 runs each as ALGORITHM=INSTANT; no table copy, no new tables).
 *
 * scanning_paused: a repository whose pull requests are not scanned and which plans skip. A
 *   webhook or a catalog sync never changes it.
 * health_*: the last connection check of an integration (test button, catalog sync, the 6-hourly
 *   check). The error text is truncated to 500 characters and never holds credentials.
 */

ALTER TABLE repositories ADD COLUMN scanning_paused BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE integration_entity ADD COLUMN health_checked_at BIGINT NULL;
ALTER TABLE integration_entity ADD COLUMN health_ok BOOLEAN NULL;
ALTER TABLE integration_entity ADD COLUMN health_error VARCHAR(500) NULL;
