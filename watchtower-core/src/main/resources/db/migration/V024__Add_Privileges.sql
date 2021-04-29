/* Change Roles to have description, default designation, and a better role name */
ALTER TABLE roles ADD COLUMN description varchar(255) DEFAULT NULL;
ALTER TABLE roles ADD COLUMN default_role BOOLEAN DEFAULT FALSE;
ALTER TABLE roles CHANGE role name varchar(255) NOT NULL;

/* Create privileges tables */
CREATE TABLE privileges (
  privilege_id BIGINT NOT NULL AUTO_INCREMENT,
  name varchar(255) NOT NULL,
  description varchar(255) DEFAULT NULL,
  module varchar(255) NOT NULL,
  category varchar(255) NOT NULL,
  PRIMARY KEY (privilege_id)
);

CREATE TABLE role_privilege (
  role_id BIGINT NOT NULL,
  privilege_id BIGINT NOT NULL,
  PRIMARY KEY (role_id,privilege_id),
  CONSTRAINT fk_rolepriv_role FOREIGN KEY (role_id) REFERENCES roles (role_id),
  CONSTRAINT fk_rolepriv_priv FOREIGN KEY (privilege_id) REFERENCES privileges (privilege_id)
);

/*
 * Cleanup old roles
 */
DELETE FROM user_role WHERE role_id in (SELECT role_id FROM roles WHERE name in ('USER', 'ADMIN', 'API'));
DELETE FROM roles where name in ('USER', 'ADMIN', 'API');