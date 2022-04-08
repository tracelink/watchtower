ALTER TABLE integration_entity DROP COLUMN api_endpoint;

CREATE TABLE ecr_integration_entity(
	integration_id BIGINT NOT NULL,
	api_key varchar(255) NOT NULL,
	secret_key varchar(255) NOT NULL,
	PRIMARY KEY (integration_id),
   	CONSTRAINT fk_ecr_api FOREIGN KEY (integration_id) REFERENCES integration_entity (integration_id)
);

CREATE TABLE image_container(
	container_id BIGINT NOT NULL AUTO_INCREMENT,
	api_label varchar(255) NOT NULL,
	image_name varchar(255) NOT NULL,
	tag_name varchar(255) NOT NULL,
	last_review_date BIGINT DEFAULT NULL,
	PRIMARY KEY (container_id)
);

CREATE TABLE image_scan(
	scan_entity_id BIGINT NOT NULL AUTO_INCREMENT,
	container_id BIGINT NOT NULL,
	submit_date BIGINT NOT NULL,
	start_date BIGINT NOT NULL,
	end_date BIGINT NOT NULL,
	status varchar(255) NOT NULL,
	error varchar(255) DEFAULT NULL,
	PRIMARY KEY (scan_entity_id),
	CONSTRAINT fk_image_scan_container FOREIGN KEY (container_id) REFERENCES image_container (container_id)
);

CREATE TABLE advisories(
	advisory_id BIGINT NOT NULL AUTO_INCREMENT,
	advisory_name varchar(255) NOT NULL,
	package_name varchar(255),
	score varchar(255) NOT NULL,
	vector varchar(255) NOT NULL,
	description BLOB NOT NULL,
	uri varchar(255) NOT NULL,
	PRIMARY KEY (advisory_id)
);

CREATE TABLE image_violation(
	vio_entity_id BIGINT NOT NULL AUTO_INCREMENT,
	scan_entity_id BIGINT NOT NULL,
	violation_name varchar(255) NOT NULL,
	severity varchar(255) NOT NULL,
	advisory_id BIGINT NOT NULL,
	PRIMARY KEY (vio_entity_id),
	CONSTRAINT fk_image_vio_advisory FOREIGN KEY (advisory_id) REFERENCES advisories (advisory_id),
	CONSTRAINT fk_image_vio_scan FOREIGN KEY (scan_entity_id) REFERENCES image_scan (scan_entity_id)
);


CREATE TABLE registry_image(
	registry_image_entity_id BIGINT NOT NULL AUTO_INCREMENT,
	image_name varchar(255) NOT NULL,
	api_label varchar(255) NOT NULL,
	last_review_date BIGINT NOT NULL,
	enabled BOOLEAN NOT NULL,
	ruleset_id BIGINT NOT NULL,
	CONSTRAINT fk_registryimage_rulesetid FOREIGN KEY (ruleset_id) REFERENCES rulesets (ruleset_id)
);

ALTER TABLE pull_request_violations ADD COLUMN severity varchar(255);
UPDATE pull_request_violations SET severity = severity_name;
ALTER TABLE pull_request_violations DROP COLUMN severity_name;
ALTER TABLE pull_request_violations DROP COLUMN severity_value;
ALTER TABLE pull_request_violations MODIFY COLUMN severity varchar(255) NOT NULL; 

ALTER TABLE upload_violations ADD COLUMN severity varchar(255);
UPDATE upload_violations SET severity = severity_name;
ALTER TABLE upload_violations DROP COLUMN severity_name;
ALTER TABLE upload_violations DROP COLUMN severity_value;
ALTER TABLE upload_violations MODIFY COLUMN severity varchar(255) NOT NULL; 

