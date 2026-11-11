-- Byte size of the source actually scanned for a PR (IMPROVEMENT_PLAN.md item 6.3/6.4).
-- Under the CHANGED_FILES scope (Phase 2) this reflects only the changed files fetched,
-- not a full repo checkout, which is the correct measure of "data scanned".
-- Existing rows default to 0, which the average-repo-size stat (item 6.5) excludes.
ALTER TABLE pull_request_scans
    ADD COLUMN source_size_bytes BIGINT NOT NULL DEFAULT 0;
