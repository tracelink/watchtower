CREATE TABLE ecr_container(
	container_id BIGINT NOT NULL AUTO_INCREMENT,
	api_label varchar(255) NOT NULL,
	repo_name varchar(255) NOT NULL,
	image_name varchar(255) NOT NULL,
	tag_name varchar(255) NOT NULL,
	last_review_date BIGINT DEFAULT NULL,
	PRIMARY KEY (container_id)
);

CREATE TABLE ecr_scans(
	scan_entity_id BIGINT NOT NULL AUTO_INCREMENT,
	container_id BIGINT NOT NULL,
	submit_date BIGINT NOT NULL,
	start_date BIGINT NOT NULL,
	end_date BIGINT NOT NULL,
	status varchar(255) NOT NULL,
	error varchar(255) DEFAULT NULL,
	PRIMARY KEY (scan_entity_id),
	CONSTRAINT fk_ecr_scan_container FOREIGN KEY (container_id) REFERENCES ecr_container (container_id)
);

CREATE TABLE ecr_violation(
	vio_entity_id BIGINT NOT NULL AUTO_INCREMENT,
	scan_entity_id BIGINT NOT NULL,
	violation_name varchar(255) NOT NULL,
	line_number BIGINT DEFAULT NULL,
	severity_name varchar(255) NOT NULL,
	severity_value varchar(255) NOT NULL,
	file_path varchar(255) DEFAULT NULL,
	PRIMARY KEY (vio_entity_id),
	CONSTRAINT fk_ecr_vio_scan FOREIGN KEY (scan_entity_id) REFERENCES ecr_scans (scan_entity_id)
);

CREATE TABLE ecr_integration_entity (
	integration_id BIGINT NOT NULL,
	account_id varchar(255) NOT NULL,
	access_key varchar(255) NOT NULL,
	secret_key varchar(255) NOT NULL,
	PRIMARY KEY (integration_id),
   	CONSTRAINT fk_ecr_api FOREIGN KEY (integration_id) REFERENCES integration_entity (integration_id)
);
