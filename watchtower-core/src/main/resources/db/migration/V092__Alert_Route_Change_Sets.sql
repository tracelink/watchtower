-- Alert-route copilot: a drafted set of route changes that a person reviews and applies, plus a version
-- on each route so a draft made against an older route is refused instead of overwriting a newer edit.
-- A change set holds route settings and channel ids only; never a webhook URL or source code.
ALTER TABLE alert_routes ADD COLUMN configuration_version BIGINT NOT NULL DEFAULT 0;
CREATE TABLE alert_route_change_set (
 id CHAR(36) NOT NULL PRIMARY KEY,
 owner VARCHAR(255) NOT NULL,
 request_key CHAR(36) NOT NULL,
 created_turn_id CHAR(36) NULL,
 version BIGINT NOT NULL DEFAULT 0,
 status VARCHAR(16) NOT NULL,
 content_hash CHAR(64) NOT NULL,
 request_hash CHAR(64) NOT NULL,
 request_json LONGTEXT NOT NULL,
 preview_json LONGTEXT NOT NULL,
 receipt_json LONGTEXT NULL,
 created_at BIGINT NOT NULL,
 expires_at BIGINT NOT NULL,
 applied_at BIGINT NULL,
 CONSTRAINT uq_alert_route_change_set_request UNIQUE (owner, request_key)
);
CREATE INDEX idx_alert_route_change_set_owner ON alert_route_change_set (owner, created_at);
INSERT INTO application_persistence_locks (lock_name) VALUES ('alert-route-configuration');
