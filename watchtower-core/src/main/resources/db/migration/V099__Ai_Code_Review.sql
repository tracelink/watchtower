-- An AI review of files an engineer picked from a scan: one run, the files in it, and what it found. These rows
-- hold paths, line numbers, a CWE and a short sentence each, never code. They expire.
CREATE TABLE ai_review_run (
    run_id VARCHAR(36) NOT NULL,
    scan_type VARCHAR(16) NOT NULL,
    scan_id BIGINT NOT NULL,
    requested_by VARCHAR(255) NOT NULL,
    status VARCHAR(16) NOT NULL,
    files_total INT NOT NULL,
    files_done INT NOT NULL,
    items INT NOT NULL,
    created_at BIGINT NOT NULL,
    finished_at BIGINT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (run_id)
);

CREATE INDEX idx_ai_review_run_scan ON ai_review_run (scan_type, scan_id);
CREATE INDEX idx_ai_review_run_expiry ON ai_review_run (expires_at);

CREATE TABLE ai_review_file (
    file_id VARCHAR(36) NOT NULL,
    run_id VARCHAR(36) NOT NULL,
    path VARCHAR(255) NOT NULL,
    status VARCHAR(16) NOT NULL,
    note VARCHAR(200) NULL,
    PRIMARY KEY (file_id)
);

CREATE INDEX idx_ai_review_file_run ON ai_review_file (run_id);

CREATE TABLE ai_review_item (
    item_id VARCHAR(36) NOT NULL,
    run_id VARCHAR(36) NOT NULL,
    path VARCHAR(255) NOT NULL,
    first_line INT NOT NULL,
    last_line INT NOT NULL,
    cwe VARCHAR(16) NOT NULL,
    rationale VARCHAR(300) NOT NULL,
    confidence VARCHAR(8) NOT NULL,
    engine_hint VARCHAR(16) NULL,
    coverage VARCHAR(12) NOT NULL,
    covered_by VARCHAR(120) NULL,
    state VARCHAR(12) NOT NULL,
    decided_by VARCHAR(255) NULL,
    decided_at BIGINT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (item_id)
);

CREATE INDEX idx_ai_review_item_run ON ai_review_item (run_id);
