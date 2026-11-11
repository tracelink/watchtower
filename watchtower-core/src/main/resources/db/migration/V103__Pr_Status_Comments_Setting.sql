-- One small status comment per pull request, edited as its scan progresses. On by default; switched on the PR settings page.
ALTER TABLE pull_request_sync_settings ADD COLUMN status_comments_enabled BOOLEAN NOT NULL DEFAULT TRUE;
