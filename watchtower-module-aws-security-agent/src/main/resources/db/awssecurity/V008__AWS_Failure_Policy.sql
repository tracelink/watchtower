-- What Watchtower does with a pull request when AWS cannot finish a review: pass it (the default) or keep it marked incomplete.
-- Null means "not chosen on the settings page", which the application treats as pass.
ALTER TABLE aws_security_permit ADD COLUMN failure_policy VARCHAR(24) NULL;
