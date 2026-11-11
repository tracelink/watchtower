CREATE TABLE module_settings (
 module_name VARCHAR(100) NOT NULL PRIMARY KEY,
 enabled BOOLEAN NOT NULL,
 version BIGINT NOT NULL DEFAULT 0,
 updated_by VARCHAR(255),
 updated_at BIGINT NOT NULL DEFAULT 0
);
INSERT INTO module_settings(module_name,enabled) VALUES
 ('regex',TRUE),('json',TRUE),('pmd',TRUE),('eslint',TRUE),
 ('checkov',TRUE),('betterleaks',TRUE),('advisory',TRUE),('opengrep',FALSE);

INSERT INTO application_persistence_locks(lock_name) VALUES ('module-settings');
