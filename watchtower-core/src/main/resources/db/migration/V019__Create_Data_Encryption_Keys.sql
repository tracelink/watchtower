CREATE TABLE data_encryption_keys (
  key_id BIGINT NOT NULL AUTO_INCREMENT,
  converter_class_name TEXT NOT NULL,
  current_key varchar(127) DEFAULT NULL,
  previous_key varchar(127) DEFAULT NULL,
  last_rotation_date_time TIMESTAMP DEFAULT NULL,
  rotation_in_progress BOOLEAN NOT NULL,
  disabled BOOLEAN NOT NULL,
  PRIMARY KEY (key_id)
);

CREATE TABLE encryption_metadata (
  metadata_id BIGINT NOT NULL AUTO_INCREMENT,
  last_rotation_date_time TIMESTAMP DEFAULT NULL,
  rotation_schedule_enabled BOOLEAN NOT NULL,
  rotation_period INT DEFAULT NULL,
  PRIMARY KEY (metadata_id)
);
