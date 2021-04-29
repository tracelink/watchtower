/*
 * Make new scan container parent table for inheritance 
 */
CREATE TABLE scan_container (
	container_id BIGINT NOT NULL AUTO_INCREMENT,
	last_review_date BIGINT DEFAULT NULL,
	PRIMARY KEY (container_id)
);

/*
 * Move data from pull requests to parent container 
 */
INSERT INTO scan_container (container_id, last_review_date)
	SELECT pr_entity_id, last_review_date FROM pull_requests;

/*
 * Change pull requests table to reference the container id instead 
 * and drop the last review date
 */
ALTER TABLE pull_requests CHANGE pr_entity_id container_id BIGINT;
ALTER TABLE pull_requests 
	ADD CONSTRAINT fk_pk_pr_container FOREIGN KEY (container_id) REFERENCES scan_container (container_id);
ALTER TABLE pull_requests DROP last_review_date;

/*
 * Rename scan table to reference container_id instead of pr_entity_id
 * Remove pr_entity_id from violations
 * Setup the foreign key relationships
 */
ALTER TABLE scan_results CHANGE pr_entity_id container_id BIGINT;
ALTER TABLE violations DROP pr_entity_id;
ALTER TABLE scan_results 
	ADD CONSTRAINT fk_results_container FOREIGN KEY (container_id) REFERENCES scan_container (container_id);
ALTER TABLE violations
	ADD CONSTRAINT fk_vios_results FOREIGN KEY (scan_entity_id) REFERENCES scan_results (scan_entity_id);

/*
 * Add submit date and start date to scan results table
 */
ALTER TABLE scan_results ADD submit_date BIGINT;
UPDATE scan_results SET submit_date = 0 WHERE submit_date is NULL;
ALTER TABLE scan_results MODIFY submit_date BIGINT NOT NULL DEFAULT 0;
ALTER TABLE scan_results ADD start_date BIGINT;
UPDATE scan_results SET start_date = 0 WHERE start_date is NULL;
ALTER TABLE scan_results MODIFY start_date BIGINT NOT NULL DEFAULT 0;

/**
 * Remove num vulns as this data is generated based on the FK
 */
ALTER TABLE scan_results DROP num_vulns;

/** 
 * Add scan status and error message to scans
 */
ALTER TABLE scan_results ADD error varchar(255) DEFAULT NULL;
ALTER TABLE scan_results ADD status varchar(255);
UPDATE scan_results SET status = 'Done';
ALTER TABLE scan_results MODIFY status varchar(255) NOT NULL;
