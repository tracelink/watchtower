/* Change user/role ids to BIGINT (3 steps)*/
/* 1. Drop foreign keys */
ALTER TABLE user_role DROP FOREIGN KEY fk_userid;
ALTER TABLE user_role DROP FOREIGN KEY fk_roleid;
ALTER TABLE api_keys DROP FOREIGN KEY fk_api_key_user;

/* 2. Change datatypes */
ALTER TABLE users MODIFY user_id BIGINT NOT NULL AUTO_INCREMENT;
ALTER TABLE roles MODIFY role_id BIGINT NOT NULL AUTO_INCREMENT;
ALTER TABLE user_role MODIFY user_id BIGINT NOT NULL;
ALTER TABLE user_role MODIFY role_id BIGINT NOT NULL;
ALTER TABLE api_keys MODIFY user_id BIGINT NOT NULL;

/* 3. Re-add foreign keys */
ALTER TABLE user_role ADD CONSTRAINT fk_userrole_user FOREIGN KEY (user_id) REFERENCES users (user_id);
ALTER TABLE user_role ADD CONSTRAINT fk_userrole_role FOREIGN KEY (role_id) REFERENCES roles (role_id);
ALTER TABLE api_keys ADD CONSTRAINT fk_api_key_user FOREIGN KEY (user_id) REFERENCES users (user_id);
