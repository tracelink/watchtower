ALTER TABLE ecr_integration_entity ADD COLUMN reject_option varchar(255);
UPDATE ecr_integration_entity SET reject_option = 'Delete Image';
ALTER TABLE ecr_integration_entity MODIFY COLUMN reject_option varchar(255) NOT NULL;

ALTER TABLE bb_cloud_integration_entity ADD COLUMN reject_option varchar(255);
UPDATE bb_cloud_integration_entity SET reject_option = 'Send Comment and Block Pull Request';
ALTER TABLE bb_cloud_integration_entity MODIFY COLUMN reject_option varchar(255) NOT NULL;
