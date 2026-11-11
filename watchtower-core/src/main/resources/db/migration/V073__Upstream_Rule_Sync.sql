-- R5.4: upstream (module-provided) rule sync. New provided rules that arrive with an upgrade are
-- held non-blocking until a person approves them; every catalog change is recorded.
ALTER TABLE rules ADD COLUMN upstream_hold_since BIGINT NULL;

-- Last provided catalog seen per module. The first sync of a module only records this baseline.
CREATE TABLE upstream_rule_snapshots (
 module VARCHAR(100) NOT NULL,
 rule_name VARCHAR(255) NOT NULL,
 rule_id BIGINT NOT NULL,
 revision VARCHAR(64) NULL,
 PRIMARY KEY (module, rule_name)
);

CREATE TABLE upstream_updates (
 update_id CHAR(36) NOT NULL PRIMARY KEY,
 module VARCHAR(100) NOT NULL,
 created_at BIGINT NOT NULL,
 added_json LONGTEXT NOT NULL,
 changed_json LONGTEXT NOT NULL,
 removed_json LONGTEXT NOT NULL,
 held_count INT NOT NULL,
 check_status VARCHAR(24) NOT NULL,
 check_json LONGTEXT NULL,
 approved_by VARCHAR(255) NULL,
 approved_at BIGINT NULL,
 version BIGINT NOT NULL DEFAULT 0,
 INDEX idx_upstream_update_created (created_at)
);

INSERT INTO application_persistence_locks(lock_name) VALUES ('upstream-sync');
