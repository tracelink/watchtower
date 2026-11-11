-- R5.1: weekly review report and coverage matrix. Reports are source-free summaries; the job never
-- opens review items or changes enforcement.
CREATE TABLE rule_review_report_settings (
 settings_id INT NOT NULL PRIMARY KEY,
 enabled BOOLEAN NOT NULL,
 weekday INT NOT NULL,
 version BIGINT NOT NULL DEFAULT 0,
 updated_by VARCHAR(255) NULL,
 updated_at BIGINT NOT NULL DEFAULT 0
);
INSERT INTO rule_review_report_settings(settings_id,enabled,weekday) VALUES (1,TRUE,1);

CREATE TABLE rule_review_reports (
 report_id CHAR(36) NOT NULL PRIMARY KEY,
 period_key VARCHAR(16) NULL,
 trigger_type VARCHAR(16) NOT NULL,
 actor VARCHAR(255) NOT NULL,
 settings_version BIGINT NOT NULL,
 created_at BIGINT NOT NULL,
 summary_json LONGTEXT NOT NULL,
 UNIQUE KEY idx_rule_review_report_period (period_key),
 INDEX idx_rule_review_report_created (created_at)
);

-- Serializes the weekly check and manual runs across pods.
INSERT INTO application_persistence_locks(lock_name) VALUES ('rule-review-reports');
