ALTER TABLE rule_review_reports ADD COLUMN item_schema INTEGER NOT NULL DEFAULT 0;
CREATE TABLE rule_review_report_items (
 report_id VARCHAR(36) NOT NULL,
 item_order INTEGER NOT NULL,
 rule_id BIGINT NOT NULL,
 rule_revision VARCHAR(64),
 rule_name VARCHAR(100),
 module VARCHAR(64),
 priority VARCHAR(24),
 owner VARCHAR(255),
 open_reviews BIGINT NOT NULL,
 reviewed_noise BOOLEAN NOT NULL,
 review_overdue BOOLEAN NOT NULL,
 missing_owner BOOLEAN NOT NULL,
 zero_matches BOOLEAN NOT NULL,
 missing_cwe BOOLEAN NOT NULL,
 reviewed_sample BIGINT,
 false_positives BIGINT,
 fp_rate DOUBLE,
 review_by DATE,
 successful_engines BIGINT,
 PRIMARY KEY (report_id,item_order),
 CONSTRAINT fk_rule_report_items_report FOREIGN KEY (report_id) REFERENCES rule_review_reports(report_id)
);
