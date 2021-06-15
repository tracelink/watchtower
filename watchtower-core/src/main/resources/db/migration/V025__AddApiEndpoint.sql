ALTER TABLE integration_entity ADD COLUMN api_endpoint varchar(255);
UPDATE integration_entity SET api_endpoint = api_label;
ALTER TABLE integration_entity MODIFY COLUMN api_endpoint varchar(255) NOT NULL; 
