-- Credentials for AI providers, managed by an Assistant Admin in the UI like SCM integration
-- credentials. api_key is encrypted by StringEncryptedAttributeConverter, the converter that
-- Bitbucket and ECR credentials use, so key rotation re-encrypts it with them.
CREATE TABLE ai_integrations (
 provider VARCHAR(32) NOT NULL PRIMARY KEY,
 api_key VARCHAR(2048) DEFAULT NULL,
 updated_by VARCHAR(255) DEFAULT NULL,
 updated_at BIGINT DEFAULT NULL,
 health_checked_at BIGINT DEFAULT NULL,
 health_ok BOOLEAN DEFAULT NULL,
 health_error VARCHAR(500) DEFAULT NULL,
 version BIGINT NOT NULL DEFAULT 0
);
INSERT INTO ai_integrations (provider, version) VALUES ('OPENAI', 0);
