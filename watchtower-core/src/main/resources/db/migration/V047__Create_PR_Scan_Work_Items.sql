CREATE TABLE pr_scan_work_items (
    work_item_id BIGINT NOT NULL AUTO_INCREMENT,
    dedup_key VARCHAR(64) NOT NULL UNIQUE,
    api_label VARCHAR(255) NOT NULL,
    repo_name VARCHAR(255) NOT NULL,
    pr_id VARCHAR(255) NOT NULL,
    commit_hash VARCHAR(255),
    status VARCHAR(32) NOT NULL,
    enqueued_at BIGINT NOT NULL,
    started_at BIGINT,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (work_item_id)
);

CREATE INDEX idx_pr_scan_work_items_status_enqueued
    ON pr_scan_work_items(status, enqueued_at);
