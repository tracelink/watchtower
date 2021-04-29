CREATE TABLE pull_requests (
  pr_entity_id BIGINT NOT NULL AUTO_INCREMENT,
  last_review_date BIGINT DEFAULT NULL,
  resolved boolean NOT NULL,
  api_label varchar(255) NOT NULL,
  author varchar(255) NOT NULL,
  source_branch varchar(255) NOT NULL,
  destination_branch varchar(255) DEFAULT NULL,
  pr_id varchar(255) DEFAULT NULL,
  repo_name varchar(255) DEFAULT NULL,
  PRIMARY KEY (pr_entity_id)
);

CREATE TABLE scan_results (
  scan_entity_id BIGINT NOT NULL AUTO_INCREMENT,
  pr_entity_id BIGINT NOT NULL,
  review_date BIGINT NOT NULL,
  num_vulns BIGINT NOT NULL,
  PRIMARY KEY (scan_entity_id)
);

CREATE TABLE violations (
  vio_entity_id BIGINT NOT NULL AUTO_INCREMENT,
  pr_entity_id BIGINT NOT NULL,
  scan_entity_id BIGINT NOT NULL,
  violation_name varchar(255) NOT NULL,
  line_number BIGINT NOT NULL,
  severity_name varchar(255) NOT NULL,
  severity_value BIGINT NOT NULL,
  file_path varchar(255) NOT NULL,
  preexisting TINYINT NOT NULL,
  PRIMARY KEY (vio_entity_id)
);