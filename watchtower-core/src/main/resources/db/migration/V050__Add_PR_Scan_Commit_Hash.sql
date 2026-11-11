-- The commit a pull request scan ran against, so a finding can later be re-read exactly as it
-- was scanned (live secret verification). Null for scans saved before this column existed.
ALTER TABLE pull_request_scans ADD COLUMN commit_hash VARCHAR(64) DEFAULT NULL;
