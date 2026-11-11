CREATE TABLE assistant_sessions (
 session_id CHAR(36) NOT NULL PRIMARY KEY, owner VARCHAR(255) NOT NULL,
 started_at BIGINT NOT NULL, last_user_message_at BIGINT NOT NULL,
 last_turn_at BIGINT NOT NULL, expires_at BIGINT NOT NULL,
 model VARCHAR(128) NOT NULL, effort VARCHAR(24) NOT NULL,
 turn_count INT NOT NULL, latest_key VARCHAR(255) NULL,
 transcript_purged_at BIGINT NULL, INDEX idx_assistant_history (owner,expires_at,last_turn_at)
);
CREATE TABLE assistant_turns (
 turn_id CHAR(36) NOT NULL PRIMARY KEY, session_id CHAR(36) NOT NULL,
 owner VARCHAR(255) NOT NULL, idempotency_key CHAR(36) NOT NULL,
 request_hash CHAR(64) NOT NULL, status VARCHAR(24) NOT NULL,
 model VARCHAR(128) NOT NULL, effort VARCHAR(24) NOT NULL,
 settings_json TEXT NOT NULL, checkpoint_key VARCHAR(255) NOT NULL,
 lease_owner CHAR(36) NULL, lease_version BIGINT NOT NULL,
 heartbeat_at BIGINT NULL, attempts INT NOT NULL,
 deadline_at BIGINT NOT NULL, created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL,
 tokens BIGINT NOT NULL, cost_micros BIGINT NOT NULL,
 error_code VARCHAR(64) NULL,
 -- NULL releases the per-user and per-session slots at terminal states.
 active_user CHAR(64) NULL, active_session CHAR(36) NULL,
 UNIQUE KEY idx_assistant_idempotency (owner,idempotency_key),
 UNIQUE KEY idx_assistant_active_user (active_user),
 UNIQUE KEY idx_assistant_active_session (active_session),
 INDEX idx_assistant_work (status,heartbeat_at,deadline_at),
 INDEX idx_assistant_session_turns (session_id,created_at)
);
CREATE TABLE assistant_outbox (
 turn_id CHAR(36) NOT NULL PRIMARY KEY, session_id CHAR(36) NOT NULL,
 sent_at BIGINT NULL, attempts INT NOT NULL, next_attempt_at BIGINT NOT NULL,
 INDEX idx_assistant_outbox (next_attempt_at,sent_at)
);
CREATE TABLE assistant_request_reservations (
 reservation_id CHAR(36) NOT NULL PRIMARY KEY, turn_id CHAR(36) NOT NULL,
 owner_scope CHAR(64) NOT NULL, bucket_start BIGINT NOT NULL,
 reserved_tokens BIGINT NOT NULL, reserved_cost_micros BIGINT NOT NULL,
 actual_tokens BIGINT NULL, actual_cost_micros BIGINT NULL,
 created_at BIGINT NOT NULL, INDEX idx_assistant_reservations (turn_id,created_at)
);
