ALTER TABLE bb_cloud_integration_entity MODIFY workspace varchar(255) NOT NULL;
ALTER TABLE bb_cloud_integration_entity MODIFY authentication varchar(255) NOT NULL;
ALTER TABLE bb_cloud_integration_entity DROP api_base;
ALTER TABLE integration_entity DROP api_type;
 
