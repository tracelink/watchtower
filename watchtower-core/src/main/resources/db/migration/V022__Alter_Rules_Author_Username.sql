ALTER TABLE rules ADD column author_username varchar(255);
UPDATE rules r SET r.author_username = (SELECT u.username FROM users u WHERE r.author = u.user_id);
ALTER TABLE rules DROP CONSTRAINT fk_author_rule;
ALTER TABLE rules DROP author;
ALTER TABLE rules CHANGE author_username author varchar(255);
ALTER TABLE rules MODIFY author varchar(255) NOT NULL;

