-- R5.5: reviewed, scoped organization knowledge (sanitizers, sources, sinks, framework guarantees).
-- A second person approves each entry; chat may cite approved, current, in-scope entries and never
-- writes them. Entries hold short human statements and references - never source code.
CREATE TABLE assistant_knowledge (
 knowledge_id CHAR(36) NOT NULL PRIMARY KEY,
 kind VARCHAR(24) NOT NULL,
 statement VARCHAR(300) NOT NULL,
 language VARCHAR(32) NOT NULL,
 library VARCHAR(128) NOT NULL,
 version_range VARCHAR(64) NOT NULL,
 all_repositories BOOLEAN NOT NULL,
 repository_ids VARCHAR(1024) NOT NULL,
 rule_ids VARCHAR(1024) NOT NULL,
 cwes VARCHAR(512) NOT NULL,
 evidence_json VARCHAR(2048) NOT NULL,
 status VARCHAR(16) NOT NULL,
 review_by VARCHAR(10) NOT NULL,
 proposed_by VARCHAR(255) NOT NULL,
 proposed_at BIGINT NOT NULL,
 decided_by VARCHAR(255) NULL,
 decided_at BIGINT NULL,
 decision_note VARCHAR(300) NULL,
 version BIGINT NOT NULL DEFAULT 0,
 INDEX idx_knowledge_status (status, language)
);

CREATE TABLE assistant_knowledge_audit (
 audit_id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
 knowledge_id CHAR(36) NOT NULL,
 action VARCHAR(16) NOT NULL,
 actor VARCHAR(255) NOT NULL,
 note VARCHAR(300) NULL,
 created_at BIGINT NOT NULL,
 INDEX idx_knowledge_audit_entry (knowledge_id, audit_id)
);
