-- An optional note from the person who started an AI review about what to look at. Plain words only (the server
-- refuses anything that looks like a secret), kept with the run so a resumed review keeps it, and removed with the
-- run when it expires.
ALTER TABLE ai_review_run ADD COLUMN focus VARCHAR(500) NULL;
