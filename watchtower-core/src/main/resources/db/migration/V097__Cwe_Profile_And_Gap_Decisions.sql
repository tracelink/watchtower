-- Which weaknesses matter in this installation (the CWE profile), and what people decided about gaps in
-- the coverage of those weaknesses. Small integer keys and bounded text only.
CREATE TABLE cwe_profile_entry (
    cwe_id INT NOT NULL,
    priority VARCHAR(16) NOT NULL,
    note VARCHAR(255) NULL,
    added_by VARCHAR(255) NOT NULL,
    added_at BIGINT NOT NULL,
    PRIMARY KEY (cwe_id)
);

-- One decision per weakness and language column; decision_key is "<cwe_id>:<LANGUAGE>".
CREATE TABLE cwe_gap_decision (
    decision_key VARCHAR(32) NOT NULL,
    cwe_id INT NOT NULL,
    language VARCHAR(16) NOT NULL,
    decision VARCHAR(16) NOT NULL,
    note VARCHAR(255) NULL,
    decided_by VARCHAR(255) NOT NULL,
    decided_at BIGINT NOT NULL,
    PRIMARY KEY (decision_key)
);

CREATE INDEX idx_cwe_gap_decision_cwe ON cwe_gap_decision (cwe_id);
