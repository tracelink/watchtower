-- R5.3: deterministic variant searches. One exact rule definition over chosen repositories, each
-- pinned to a commit. Only counts, relative paths and lines are stored; never source.
CREATE TABLE variant_searches (
 search_id CHAR(36) NOT NULL PRIMARY KEY,
 case_id CHAR(36) NULL,
 rule_id BIGINT NOT NULL,
 candidate_id CHAR(36) NULL,
 module VARCHAR(64) NOT NULL,
 designation VARCHAR(16) NOT NULL,
 definition_hash CHAR(64) NOT NULL,
 definition_json LONGTEXT NOT NULL,
 requested_by VARCHAR(255) NOT NULL,
 status VARCHAR(16) NOT NULL,
 created_at BIGINT NOT NULL,
 updated_at BIGINT NOT NULL,
 finished_at BIGINT NULL,
 INDEX idx_variant_search_case (case_id, created_at),
 INDEX idx_variant_search_status (status, created_at)
);

CREATE TABLE variant_search_repositories (
 entry_id CHAR(36) NOT NULL PRIMARY KEY,
 search_id CHAR(36) NOT NULL,
 position INT NOT NULL,
 repository_id BIGINT NOT NULL,
 repository_name VARCHAR(255) NOT NULL,
 api_label VARCHAR(255) NOT NULL,
 commit_hash CHAR(40) NULL,
 status VARCHAR(24) NOT NULL,
 match_count INT NOT NULL DEFAULT 0,
 truncated BOOLEAN NOT NULL DEFAULT FALSE,
 error_code VARCHAR(32) NULL,
 engine_identity CHAR(64) NULL,
 claimed_at BIGINT NULL,
 locations_json LONGTEXT NULL,
 finished_at BIGINT NULL,
 UNIQUE KEY idx_variant_search_repo (search_id, repository_id)
);

INSERT INTO application_persistence_locks(lock_name) VALUES ('variant-searches');
