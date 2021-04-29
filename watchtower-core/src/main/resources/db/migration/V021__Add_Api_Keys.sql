CREATE TABLE api_keys (
  api_key_id BIGINT NOT NULL AUTO_INCREMENT,
  label varchar(255) DEFAULT NULL,
  api_key varchar(36) DEFAULT NULL,
  secret varchar(255) DEFAULT NULL,
  user_id int(11) NOT NULL,
  PRIMARY KEY (api_key_id),
  CONSTRAINT fk_api_key_user FOREIGN KEY (user_id) REFERENCES users (user_id)
);