-- Weekly Home digest: one row per digest, holding the aggregate counts it was written from and the few short
-- lines the assistant wrote about them. Counts only: no finding, file, repository or person is ever stored.
-- schedule_key (the ISO week) is unique, so the Monday job writes one digest per week however many pods run it;
-- a digest someone asks for by hand has no schedule_key.
CREATE TABLE ai_digest (
 digest_id CHAR(36) NOT NULL PRIMARY KEY,
 schedule_key VARCHAR(10) NULL,
 trigger_type VARCHAR(10) NOT NULL,
 created_by VARCHAR(255) NOT NULL,
 created_at BIGINT NOT NULL,
 status VARCHAR(12) NOT NULL,
 window_start BIGINT NOT NULL,
 window_end BIGINT NOT NULL,
 counts_json LONGTEXT NOT NULL,
 points_json LONGTEXT NULL,
 model VARCHAR(128) NULL,
 CONSTRAINT uq_ai_digest_schedule UNIQUE (schedule_key)
);
CREATE INDEX idx_ai_digest_created ON ai_digest (created_at);
INSERT INTO application_persistence_locks (lock_name) VALUES ('home-digest');
