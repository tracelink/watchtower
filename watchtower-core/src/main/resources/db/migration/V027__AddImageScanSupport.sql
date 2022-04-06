ALTER TABLE integration_entity DROP COLUMN api_endpoint;

CREATE TABLE image_container(
	container_id BIGINT NOT NULL AUTO_INCREMENT,
	api_label varchar(255) NOT NULL,
	registry_name varchar(255) NOT NULL,
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

CREATE TABLE image_violation(
	vio_entity_id BIGINT NOT NULL AUTO_INCREMENT,
	scan_entity_id BIGINT NOT NULL,
	violation_name varchar(255) NOT NULL,
	severity_name varchar(255) NOT NULL,
	advisory_id BIGINT NOT NULL,
	PRIMARY KEY (vio_entity_id),
	CONSTRAINT fk_image_vio_advisory FOREIGN KEY (advisory_id) REFERENCES advisories (advisory_id),
	CONSTRAINT fk_image_vio_scan FOREIGN KEY (scan_entity_id) REFERENCES image_scans (scan_entity_id)
);

CREATE TABLE advisories(
	advisory_id BIGINT NOT NULL AUTO_INCREMENT,
	finding_name varchar(255) NOT NULL,
	package_name varchar(255),
	score varchar(255) NOT NULL,
	vector varchar(255) NOT NULL,
	description BLOB NOT NULL,
	uri varchar(255) NOT NULL,
	PRIMARY KEY (advisory_id)
);

