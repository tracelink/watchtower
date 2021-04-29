/**
 * Handle splitting out Pull Requests
 */
/*PR Container*/
CREATE TABLE pull_request_container (
	container_id BIGINT NOT NULL AUTO_INCREMENT,
	c_id BIGINT NOT NULL, /* Temporary holder for the existing container_id */
	resolved boolean NOT NULL,
	api_label varchar(255) NOT NULL,
	author varchar(255) NOT NULL,
	source_branch varchar(255) NOT NULL,
	destination_branch varchar(255) DEFAULT NULL,
	pr_id varchar(255) DEFAULT NULL,
	repo_name varchar(255) DEFAULT NULL,
	last_review_date BIGINT DEFAULT NULL,
 	PRIMARY KEY (container_id)
);

INSERT INTO pull_request_container (c_id, resolved, api_label, author, source_branch, destination_branch, pr_id, repo_name, last_review_date)
	SELECT pull_requests.container_id, resolved, api_label, author, source_branch, destination_branch, pr_id, repo_name, last_review_date
		FROM pull_requests, scan_container 
		WHERE pull_requests.container_id = scan_container.container_id;
		
/*Cleanup old PR table to clear the values and name clashes*/
DROP TABLE pull_requests;

/*Scan*/
CREATE TABLE pull_request_scans (
	scan_entity_id BIGINT NOT NULL AUTO_INCREMENT,
	s_id BIGINT NOT NULL, /* Temporary holder for the existing scan_entity_id */
	container_id BIGINT NOT NULL,
	c_id BIGINT NOT NULL, /* Temporary holder for the existing container_id */
	submit_date BIGINT NOT NULL DEFAULT 0,
	start_date BIGINT NOT NULL DEFAULT 0,
	end_date BIGINT NOT NULL,
	status varchar(255) NOT NULL,
	error varchar(255) DEFAULT NULL,
	PRIMARY KEY (scan_entity_id),
   	CONSTRAINT fk_pr_scan_container FOREIGN KEY (container_id) REFERENCES pull_request_container (container_id)
);

INSERT INTO pull_request_scans (s_id, container_id, c_id, submit_date, start_date, end_date, status, error)
	SELECT scan_results.scan_entity_id, pull_request_container.container_id, scan_results.container_id, submit_date, start_date, review_date, status, error
		FROM scan_results, pull_request_container
		WHERE scan_results.container_id = pull_request_container.c_id;
		
/*Violation*/
CREATE TABLE pull_request_violations(
	vio_entity_id BIGINT NOT NULL AUTO_INCREMENT,
	v_id BIGINT NOT NULL, /* Temporary holder for the existing vio_entity_id */
	scan_entity_id BIGINT NOT NULL,
	s_id BIGINT NOT NULL, /* Tempoorary holder for the existing scan_entity_id */
	violation_name varchar(255) NOT NULL,
	line_number BIGINT NOT NULL,
	severity_name varchar(255) NOT NULL,
	severity_value BIGINT NOT NULL,
	file_path varchar(255) NOT NULL,
	PRIMARY KEY (vio_entity_id),
   	CONSTRAINT fk_pr_vio_scan FOREIGN KEY (scan_entity_id) REFERENCES pull_request_scans (scan_entity_id)
);

INSERT INTO pull_request_violations (v_id, scan_entity_id, s_id, violation_name, line_number, severity_name, severity_value, file_path)
	SELECT violations.vio_entity_id, pull_request_scans.scan_entity_id, violations.scan_entity_id, violation_name, line_number, severity_name, severity_value, file_path
		FROM violations, pull_request_scans
		WHERE violations.scan_entity_id = pull_request_scans.s_id;

/**
 * Cleanup temp tables/columns from PR moves
 */
ALTER TABLE pull_request_container DROP c_id;
ALTER TABLE pull_request_scans DROP s_id;
ALTER TABLE pull_request_scans DROP c_id;
ALTER TABLE pull_request_violations DROP v_id;
ALTER TABLE pull_request_violations DROP s_id;


/**
 * Handle splitting out Uploads
 */
/*Upload Container*/
CREATE TABLE upload_container (
	container_id BIGINT NOT NULL AUTO_INCREMENT,
	c_id BIGINT,
	name varchar(255) NOT NULL,
	submitter varchar(255) NOT NULL,
	ticket varchar(255) NOT NULL,
	ruleset varchar(255) NOT NULL,
	file_location varchar(255) NOT NULL,
	last_review_date BIGINT DEFAULT NULL,
	PRIMARY KEY (container_id)
);

INSERT INTO upload_container (c_id, name, submitter, ticket, ruleset, file_location, last_review_date) 
	SELECT upload_scans.container_id, name, submitter, ticket, ruleset, file_location, last_review_date 
		FROM upload_scans, scan_container 
		WHERE upload_scans.container_id = scan_container.container_id;

/*Cleanup old uploads table to clear the values and name clashes*/
DROP TABLE upload_scans;

/*Scan*/
CREATE TABLE upload_scans (
	scan_entity_id BIGINT NOT NULL AUTO_INCREMENT,
	s_id BIGINT NOT NULL, /* Temporary holder for the existing scan_entity_id */
	container_id BIGINT NOT NULL,
	c_id BIGINT NOT NULL, /* Temporary holder for the existing container_id */
	submit_date BIGINT NOT NULL DEFAULT 0,
	start_date BIGINT NOT NULL DEFAULT 0,
	end_date BIGINT NOT NULL,
	status varchar(255) NOT NULL,
	error varchar(255) DEFAULT NULL,
	PRIMARY KEY (scan_entity_id),
   	CONSTRAINT fk_upload_scan_container FOREIGN KEY (container_id) REFERENCES upload_container (container_id)
);

INSERT INTO upload_scans (s_id, container_id, c_id, submit_date, start_date, end_date, status, error)
	SELECT scan_results.scan_entity_id, upload_container.container_id, scan_results.container_id, submit_date, start_date, review_date, status, error
		FROM scan_results, upload_container
		WHERE scan_results.container_id = upload_container.c_id;
		
/*Violation*/
CREATE TABLE upload_violations(
	vio_entity_id BIGINT NOT NULL AUTO_INCREMENT,
	v_id BIGINT NOT NULL, /* Temporary holder for the existing vio_entity_id */
	scan_entity_id BIGINT NOT NULL,
	s_id BIGINT NOT NULL, /* Tempoorary holder for the existing scan_entity_id */
	violation_name varchar(255) NOT NULL,
	line_number BIGINT NOT NULL,
	severity_name varchar(255) NOT NULL,
	severity_value BIGINT NOT NULL,
	file_path varchar(255) NOT NULL,
	PRIMARY KEY (vio_entity_id),
   	CONSTRAINT fk_upload_vio_scan FOREIGN KEY (scan_entity_id) REFERENCES upload_scans (scan_entity_id)
);

INSERT INTO upload_violations (v_id, scan_entity_id, s_id, violation_name, line_number, severity_name, severity_value, file_path)
	SELECT violations.vio_entity_id, upload_scans.scan_entity_id, violations.scan_entity_id, violation_name, line_number, severity_name, severity_value, file_path
		FROM violations, upload_scans
		WHERE violations.scan_entity_id = upload_scans.s_id;

/**
 * Cleanup temp tables/columns from Upload moves
 */
ALTER TABLE upload_container DROP c_id;
ALTER TABLE upload_scans DROP s_id;
ALTER TABLE upload_scans DROP c_id;
ALTER TABLE upload_violations DROP v_id;
ALTER TABLE upload_violations DROP s_id;

/*Cleanup old scans and violations tables as all data was moved*/
DROP TABLE violations;
DROP TABLE scan_results;
DROP TABLE scan_container;
