CREATE TABLE repositories (
  repo_entity_id BIGINT NOT NULL AUTO_INCREMENT,
  last_review_date BIGINT DEFAULT NULL,
  api_label varchar(255) NOT NULL,
  repo_name varchar(255) NOT NULL,
  ruleset varchar(255) DEFAULT NULL,
  PRIMARY KEY (repo_entity_id)
);