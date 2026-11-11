-- R5.2b: AI-suggested names for review-report feedback themes. Stored reports stay immutable;
-- names are attached when a report is viewed, matched by theme fingerprint. Rows hold only the
-- validated name, cause and one sentence - never feedback text or source. A theme that has not
-- changed reuses its row, so naming is paid for once per model, effort and prompt version.
CREATE TABLE rule_review_theme_names (
 name_key CHAR(64) NOT NULL PRIMARY KEY,
 theme_fingerprint CHAR(64) NOT NULL,
 rule_id BIGINT NOT NULL,
 status VARCHAR(16) NOT NULL,
 name VARCHAR(60) NULL,
 cause VARCHAR(40) NULL,
 explanation VARCHAR(255) NULL,
 model VARCHAR(128) NOT NULL,
 effort VARCHAR(16) NOT NULL,
 prompt_version VARCHAR(16) NOT NULL,
 text_sent BOOLEAN NOT NULL,
 input_tokens BIGINT NOT NULL,
 output_tokens BIGINT NOT NULL,
 cost_micros BIGINT NOT NULL,
 created_at BIGINT NOT NULL,
 last_used_at BIGINT NOT NULL,
 INDEX idx_theme_names_fingerprint (theme_fingerprint, created_at),
 INDEX idx_theme_names_last_used (last_used_at)
);
