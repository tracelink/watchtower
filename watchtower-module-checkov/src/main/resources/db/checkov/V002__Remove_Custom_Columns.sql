ALTER TABLE checkov_rules DROP core;
ALTER TABLE checkov_rules DROP code;
ALTER TABLE checkov_rules ADD checkovrulename varchar(255);