-- The MITRE CWE catalog (weaknesses only), loaded on demand from the Knowledge page. Small integer keys
-- and bounded text only; usage is named mapping_usage because USAGE is a reserved word in MySQL.
CREATE TABLE cwe_entry (
    cwe_id INT NOT NULL,
    name VARCHAR(255) NOT NULL,
    abstraction VARCHAR(16) NULL,
    structure VARCHAR(16) NULL,
    entry_status VARCHAR(16) NULL,
    mapping_usage VARCHAR(32) NOT NULL,
    description VARCHAR(2000) NULL,
    likelihood VARCHAR(16) NULL,
    parent_ids VARCHAR(255) NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (cwe_id)
);

-- One row (meta_id = 1): which release is stored and how the last refresh ended.
CREATE TABLE cwe_catalog_meta (
    meta_id INT NOT NULL,
    content_version VARCHAR(16) NULL,
    release_date VARCHAR(16) NULL,
    entry_count INT NOT NULL,
    refresh_status VARCHAR(16) NOT NULL,
    last_error VARCHAR(255) NULL,
    fetched_at BIGINT NULL,
    refreshed_by VARCHAR(255) NULL,
    PRIMARY KEY (meta_id)
);

INSERT INTO cwe_catalog_meta (meta_id, entry_count, refresh_status) VALUES (1, 0, 'NEVER');
