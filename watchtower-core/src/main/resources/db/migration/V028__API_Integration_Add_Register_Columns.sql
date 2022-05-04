ALTER TABLE integration_entity ADD COLUMN register_state varchar(255);
ALTER TABLE integration_entity ADD COLUMN register_error varchar(255);
ALTER TABLE integration_entity ADD COLUMN watchtower_secret varchar(255);

UPDATE integration_entity SET register_state = 'NOT_SUPPORTED';
ALTER TABLE integration_entity MODIFY COLUMN register_state varchar(255) NOT NULL;
