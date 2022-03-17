ALTER TABLE regex_rules ADD provided boolean;
UPDATE regex_rules SET provided=false;
ALTER TABLE regex_rules MODIFY provided boolean NOT NULL;
