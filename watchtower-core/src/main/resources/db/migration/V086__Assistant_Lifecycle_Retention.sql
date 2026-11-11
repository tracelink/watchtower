-- Fair, durable rotation through lifecycle-pending artifacts; no transcript content.
ALTER TABLE assistant_artifacts ADD COLUMN retention_checked_at BIGINT NULL;
CREATE INDEX idx_assistant_artifact_retention ON assistant_artifacts (deleted_at, retention_checked_at);
