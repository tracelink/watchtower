-- Workspace configuration has its own scope, never a synthetic code repository.
CREATE TABLE bb_webhook_control (
 integration_id BIGINT NOT NULL PRIMARY KEY,
 lease_owner VARCHAR(36) NULL,
 lease_until BIGINT NOT NULL DEFAULT 0,
 rotation_secret VARCHAR(2048) NULL,
 rotation_operation VARCHAR(36) NULL,
 rotation_started_at BIGINT NULL
);
CREATE TABLE bb_webhook_scope (
 scope_id VARCHAR(36) NOT NULL PRIMARY KEY,
 integration_id BIGINT NOT NULL,
 scope_key VARCHAR(255) NOT NULL,
 hooks_json MEDIUMTEXT NOT NULL,
 checked_at BIGINT NULL,
 attempted_at BIGINT NULL,
 error_code VARCHAR(64) NULL,
 callback_hash VARCHAR(64) NULL,
 owned_count INT NOT NULL DEFAULT 0,
 active_owned_count INT NOT NULL DEFAULT 0,
 changed_by VARCHAR(255) NULL,
 changed_at BIGINT NULL,
 UNIQUE KEY uq_bb_webhook_scope (integration_id, scope_key)
);
CREATE TABLE bb_webhook_operation (
 operation_id VARCHAR(36) NOT NULL PRIMARY KEY,
 integration_id BIGINT NOT NULL,
 action VARCHAR(16) NOT NULL,
 workspace_name VARCHAR(255) NOT NULL,
 callback_hash VARCHAR(64) NULL,
 preset VARCHAR(32) NULL,
 active BOOLEAN NOT NULL,
 actor VARCHAR(255) NOT NULL,
 created_at BIGINT NOT NULL,
 job_id BIGINT NULL,
 status VARCHAR(24) NOT NULL
);
CREATE INDEX idx_bb_webhook_operation_integration ON bb_webhook_operation(integration_id, created_at);
CREATE TABLE bb_webhook_task (
 task_id VARCHAR(36) NOT NULL PRIMARY KEY,
 operation_id VARCHAR(36) NOT NULL,
 scope_key VARCHAR(255) NOT NULL,
 hook_uuid VARCHAR(128) NULL,
 status VARCHAR(16) NOT NULL,
 result_code VARCHAR(64) NULL,
 finished_at BIGINT NULL,
 UNIQUE KEY uq_bb_webhook_task (operation_id, scope_key)
);
ALTER TABLE bb_cloud_integration_entity ADD COLUMN previous_webhook_secret VARCHAR(2048) NULL;
ALTER TABLE bb_cloud_integration_entity ADD COLUMN previous_webhook_secret_until BIGINT NULL;
CREATE TABLE pr_comment_receipts (
 receipt_id VARCHAR(64) NOT NULL PRIMARY KEY,
 owner_token VARCHAR(36) NOT NULL,
 expires_at BIGINT NOT NULL
);
CREATE INDEX idx_pr_comment_receipt_expiry ON pr_comment_receipts(expires_at);
