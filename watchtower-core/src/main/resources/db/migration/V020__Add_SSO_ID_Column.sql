ALTER TABLE users ADD COLUMN sso_id varchar(255) DEFAULT NULL;
ALTER TABLE users MODIFY password varchar(255);
