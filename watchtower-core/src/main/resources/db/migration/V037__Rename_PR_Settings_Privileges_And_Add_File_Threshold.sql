-- Rename the PR Sync Settings privileges to PR Settings now that this page covers more
-- than just sync cadence (the full-source download threshold below). Renaming the `name`
-- column in place, rather than deleting and re-inserting, preserves privilege_id - every
-- role_privilege row already pointing at these privileges keeps working with no data loss.
UPDATE privileges SET name = 'PR Settings View' WHERE name = 'PR Sync Settings View';
UPDATE privileges SET name = 'PR Settings Modify' WHERE name = 'PR Sync Settings Modify';

-- Threshold, in changed-file count, above which a PR scan downloads the full repository
-- (through the same S3 cache FULL_SOURCE scans use) instead of fetching each changed file
-- individually from the SCM - fewer SCM calls for a large changeset, at the cost of one
-- bigger download. Default 5 is a starting point; admin-editable at /prsettings.
ALTER TABLE pull_request_sync_settings ADD COLUMN full_source_file_threshold INT NOT NULL DEFAULT 5;
