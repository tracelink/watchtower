CREATE TABLE integration_entity (
  integration_id BIGINT NOT NULL AUTO_INCREMENT,
  api_label varchar(255) NOT NULL,
  api_base varchar(255) NOT NULL,
  username varchar(255) NOT NULL,
  authentication varchar(255) NOT NULL,
  PRIMARY KEY (integration_id)
);
