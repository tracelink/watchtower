CREATE TABLE alert_channels (
  channel_id BIGINT NOT NULL AUTO_INCREMENT,
  name VARCHAR(100) NOT NULL,
  channel_type VARCHAR(32) NOT NULL,
  webhook_url TEXT NOT NULL,
  enabled BOOLEAN NOT NULL,
  created_by VARCHAR(255) NOT NULL,
  updated_by VARCHAR(255) NOT NULL,
  updated_at BIGINT NOT NULL,
  last_test_at BIGINT NULL,
  last_test_status VARCHAR(255) NULL,
  PRIMARY KEY (channel_id),
  CONSTRAINT uq_alert_channel_name UNIQUE (name)
);

CREATE TABLE alert_routes (
  route_id BIGINT NOT NULL AUTO_INCREMENT,
  alert_type VARCHAR(64) NOT NULL,
  channel_id BIGINT NOT NULL,
  enabled BOOLEAN NOT NULL,
  min_priority TINYINT NULL,
  api_label_filter VARCHAR(255) NULL,
  repo_include VARCHAR(1000) NULL,
  repo_exclude VARCHAR(1000) NULL,
  aggregation VARCHAR(16) NOT NULL,
  dedupe_window_hours INT NOT NULL,
  updated_by VARCHAR(255) NOT NULL,
  updated_at BIGINT NOT NULL,
  PRIMARY KEY (route_id),
  CONSTRAINT fk_alert_route_channel FOREIGN KEY (channel_id) REFERENCES alert_channels (channel_id)
);

CREATE TABLE alert_log (
  log_id BIGINT NOT NULL AUTO_INCREMENT,
  alert_type VARCHAR(64) NOT NULL,
  route_id BIGINT NOT NULL,
  channel_id BIGINT NOT NULL,
  thread_key VARCHAR(128) NULL,
  status VARCHAR(16) NOT NULL,
  attempts INT NOT NULL,
  next_attempt_at BIGINT NOT NULL,
  sent_at BIGINT NULL,
  created_at BIGINT NOT NULL,
  last_error VARCHAR(500) NULL,
  payload TEXT NOT NULL,
  PRIMARY KEY (log_id)
);

CREATE INDEX idx_alert_log_due ON alert_log (status, next_attempt_at);

CREATE TABLE alert_dedupe (
  dedupe_id BIGINT NOT NULL AUTO_INCREMENT,
  route_id BIGINT NOT NULL,
  dedupe_key VARCHAR(64) NOT NULL,
  created_at BIGINT NOT NULL,
  PRIMARY KEY (dedupe_id)
);

CREATE INDEX idx_alert_dedupe_lookup ON alert_dedupe (route_id, dedupe_key);
