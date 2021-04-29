/*
 * Make new scan container parent table for inheritance 
 */
CREATE TABLE upload_scans (
	container_id BIGINT NOT NULL AUTO_INCREMENT,
	name varchar(255) NOT NULL,
	submitter varchar(255) NOT NULL,
	ticket varchar(255) NOT NULL,
	ruleset varchar(255) NOT NULL,
	file_location varchar(255) NOT NULL,
	PRIMARY KEY (container_id),
	CONSTRAINT fk_upload_container FOREIGN KEY (container_id) REFERENCES scan_container (container_id)
);
