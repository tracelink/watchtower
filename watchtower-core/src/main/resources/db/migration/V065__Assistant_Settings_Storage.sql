CREATE TABLE assistant_settings (
 settings_id INT NOT NULL PRIMARY KEY, version BIGINT NOT NULL, config_json TEXT NOT NULL
);
INSERT INTO assistant_settings VALUES (1,1,'{"enabled":false,"retentionDays":14,"allowedModels":[],"defaultModel":"","defaultEffort":"","maxIterations":6,"maxRequests":9,"maxInputBytes":65536,"maxOutputTokens":2048,"maxToolBytes":16384,"maxTranscriptBytes":262144,"turnTokenCap":100000,"userDailyTokens":200000,"orgDailyTokens":2000000,"turnCostMicros":500000,"userDailyCostMicros":2000000,"orgDailyCostMicros":20000000,"queueLimit":50,"deadlineSeconds":600,"providerTimeoutSeconds":30}');
CREATE TABLE assistant_budget_daily (
 scope_key CHAR(64) NOT NULL, bucket_start BIGINT NOT NULL,
 charged_tokens BIGINT NOT NULL, charged_cost_micros BIGINT NOT NULL,
 PRIMARY KEY(scope_key,bucket_start)
);
CREATE TABLE assistant_audit (
 audit_id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY, actor VARCHAR(255) NOT NULL,
 session_id CHAR(36) NULL, turn_id CHAR(36) NULL, event VARCHAR(64) NOT NULL,
 target VARCHAR(255) NULL, model VARCHAR(128) NULL, effort VARCHAR(24) NULL,
 tokens BIGINT NOT NULL DEFAULT 0, cost_micros BIGINT NOT NULL DEFAULT 0,
 prompt_version VARCHAR(24) NOT NULL DEFAULT 'r1-v1',
 tool_version VARCHAR(24) NOT NULL DEFAULT 'r1-v1',
 created_at BIGINT NOT NULL, INDEX idx_assistant_audit (created_at,audit_id)
);
CREATE TABLE assistant_artifacts (
 artifact_key VARCHAR(255) NOT NULL PRIMARY KEY, session_id CHAR(36) NOT NULL,
 created_at BIGINT NOT NULL, deleted_at BIGINT NULL,
 INDEX idx_assistant_artifact_session (session_id,created_at)
);
CREATE TABLE assistant_outcomes (
 turn_id CHAR(36) NOT NULL PRIMARY KEY, owner VARCHAR(255) NOT NULL,
 rating INT NULL, task_type VARCHAR(24) NULL, elapsed_seconds BIGINT NULL,
 saved_seconds BIGINT NULL, updated_at BIGINT NOT NULL
);
