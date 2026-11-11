-- R6: advisory AI assessments of individual findings, requested by a person. Kept apart from human
-- judgments and rule health. Rows hold a verdict, named criteria with one sentence each, cited line
-- numbers and knowledge ids - never source code. One answer per finding occurrence, model, effort and
-- prompt version; asking again returns it.
CREATE TABLE finding_assessments (
 assessment_id CHAR(36) NOT NULL PRIMARY KEY,
 occurrence_key CHAR(64) NOT NULL,
 scan_type VARCHAR(16) NOT NULL,
 scan_id BIGINT NOT NULL,
 finding_key VARCHAR(64) NOT NULL,
 rule_id BIGINT NULL,
 rule_revision VARCHAR(64) NULL,
 status VARCHAR(16) NOT NULL,
 verdict VARCHAR(32) NULL,
 criteria_json VARCHAR(2048) NULL,
 cited_lines VARCHAR(256) NULL,
 knowledge_ids VARCHAR(512) NULL,
 model VARCHAR(128) NOT NULL,
 effort VARCHAR(16) NOT NULL,
 prompt_version VARCHAR(16) NOT NULL,
 input_tokens BIGINT NOT NULL,
 output_tokens BIGINT NOT NULL,
 cost_micros BIGINT NOT NULL,
 requested_by VARCHAR(255) NOT NULL,
 created_at BIGINT NOT NULL,
 UNIQUE KEY uk_finding_assessment (occurrence_key, model, effort, prompt_version),
 INDEX idx_finding_assessment_rule (rule_id, created_at)
);

-- Who first saw which assessment, so agreement counts only judgments made without seeing it.
CREATE TABLE finding_assessment_views (
 assessment_id CHAR(36) NOT NULL,
 viewer VARCHAR(255) NOT NULL,
 first_viewed_at BIGINT NOT NULL,
 PRIMARY KEY (assessment_id, viewer)
);
