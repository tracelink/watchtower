-- The pull request sync runs as often as every few minutes now, so its frequency is kept in minutes. Existing rows keep
-- their configured meaning (24 hours becomes 1440 minutes); the hours column stays for older readers.
ALTER TABLE pull_request_sync_settings ADD COLUMN sync_frequency_minutes INT NULL;
UPDATE pull_request_sync_settings SET sync_frequency_minutes = sync_frequency_hours * 60;
