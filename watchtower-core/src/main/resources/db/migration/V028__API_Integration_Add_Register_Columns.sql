ALTER TABLE integration_entity ADD COLUMN register_state varchar(255) NOT NULL;
ALTER TABLE integration_entity ADD COLUMN register_error varchar(255);
ALTER TABLE integration_entity ADD COLUMN watchtower_secret varchar(255);
