-- A rule an engineer asked the assistant to draft for a coverage gap. It belongs to one person, holds only the
-- rule text and small synthetic code snippets (never real customer code), and expires. Nothing here is a rule
-- until the person saves it in the designer.
CREATE TABLE rule_draft (
    draft_id VARCHAR(36) NOT NULL,
    created_by VARCHAR(255) NOT NULL,
    engine VARCHAR(16) NOT NULL,
    language VARCHAR(32) NULL,
    rule_name VARCHAR(100) NOT NULL,
    message VARCHAR(500) NOT NULL,
    priority INT NOT NULL,
    cwe VARCHAR(32) NULL,
    secondary_cwes VARCHAR(160) NULL,
    definition TEXT NOT NULL,
    file_extension VARCHAR(32) NULL,
    vulnerable_snippet TEXT NULL,
    safe_snippet TEXT NULL,
    rationale VARCHAR(500) NULL,
    source_label VARCHAR(120) NULL,
    status VARCHAR(12) NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    used_rule_name VARCHAR(100) NULL,
    PRIMARY KEY (draft_id)
);

CREATE INDEX idx_rule_draft_owner ON rule_draft (created_by, status);
CREATE INDEX idx_rule_draft_expiry ON rule_draft (expires_at);
