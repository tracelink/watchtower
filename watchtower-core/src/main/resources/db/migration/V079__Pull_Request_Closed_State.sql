-- How a pull request closed, so the UI can say Merged or Declined (resolved alone also means
-- "a scan found nothing new") and the merge gate view can count merges Watchtower had not
-- finished scanning. Null for pull requests closed before this release and for open ones.
--   closed_state          MERGED or DECLINED
--   closed_at             when the SCM says it closed, epoch millis
--   merged_commit         the commit merged, from the SCM
--   scan_pending_at_close whether a scan of it was queued or running when the close was seen
-- Nullable columns appended at the end: MySQL 8 adds them instantly, without a table copy.
ALTER TABLE pull_request_container ADD COLUMN closed_state VARCHAR(16) NULL;
ALTER TABLE pull_request_container ADD COLUMN closed_at BIGINT NULL;
ALTER TABLE pull_request_container ADD COLUMN merged_commit VARCHAR(64) NULL;
ALTER TABLE pull_request_container ADD COLUMN scan_pending_at_close BOOLEAN NULL;

-- The merge gate view reads one window of merges: 16 + 8 bytes, built online.
CREATE INDEX idx_pr_container_closed ON pull_request_container (closed_state, closed_at);
