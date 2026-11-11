-- Admin-configurable, runtime-adjustable settings governing PullRequestSynchronizer.syncData()
-- (IMPROVEMENT_PLAN.md item 5.2). Singleton row, mirroring encryption_metadata's shape (V019).
-- last_sync_completed_at lets the synchronizer's self-check survive an app restart, unlike a
-- purely in-memory scheduler timer.
CREATE TABLE pull_request_sync_settings (
  settings_id BIGINT NOT NULL AUTO_INCREMENT,
  sync_frequency_hours INT NOT NULL DEFAULT 24,
  last_sync_completed_at BIGINT DEFAULT NULL,
  PRIMARY KEY (settings_id)
);
