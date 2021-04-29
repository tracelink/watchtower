CREATE TABLE users (
  user_id int(11) NOT NULL AUTO_INCREMENT,
  username varchar(255) NOT NULL,
  enabled int(11) DEFAULT NULL,
  password varchar(255) NOT NULL,
  created datetime DEFAULT NULL,
  last_login datetime DEFAULT NULL,
  last_modified datetime DEFAULT NULL,
  PRIMARY KEY (user_id)
);

CREATE TABLE roles (
  role_id int(11) NOT NULL AUTO_INCREMENT,
  role varchar(255) DEFAULT NULL,
  PRIMARY KEY (role_id)
);

CREATE TABLE user_role (
  user_id int(11) NOT NULL,
  role_id int(11) NOT NULL,
  PRIMARY KEY (user_id,role_id),
  CONSTRAINT fk_userid FOREIGN KEY (user_id) REFERENCES users (user_id),
  CONSTRAINT fk_roleid FOREIGN KEY (role_id) REFERENCES roles (role_id)
);


INSERT INTO roles (role_id, role) VALUES (1, 'USER');
INSERT INTO roles (role_id, role) VALUES (2, 'ADMIN');
INSERT INTO roles (role_id, role) VALUES (3, 'API');