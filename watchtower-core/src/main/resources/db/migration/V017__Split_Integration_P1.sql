CREATE TABLE bb_cloud_integration_entity (
	integration_id BIGINT NOT NULL,
	workspace varchar(255),
	api_base varchar(255) NOT NULL,
	username varchar(255) NOT NULL,
	authentication varchar(255) DEFAULT NULL,
 	PRIMARY KEY (integration_id),
   	CONSTRAINT fk_bbcloud_api FOREIGN KEY (integration_id) REFERENCES integration_entity (integration_id)
);

INSERT INTO bb_cloud_integration_entity (integration_id, api_base, username, authentication)
	SELECT integration_id, api_base, username, authentication
		FROM integration_entity; 
		
ALTER TABLE integration_entity DROP api_base;
ALTER TABLE integration_entity DROP username;
ALTER TABLE integration_entity DROP authentication;
ALTER TABLE integration_entity ADD api_type varchar(255);
UPDATE integration_entity SET api_type=api_label;
ALTER TABLE integration_entity MODIFY api_type varchar(255) NOT NULL;
