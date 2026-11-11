-- File types a scanner module runs on. NULL keeps the scanner's own default, an empty string means every file.
ALTER TABLE module_settings ADD COLUMN file_types VARCHAR(1000) NULL;
