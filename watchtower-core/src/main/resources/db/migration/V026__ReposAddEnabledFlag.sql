ALTER TABLE repositories ADD COLUMN enabled boolean;
UPDATE repositories SET enabled = true;
