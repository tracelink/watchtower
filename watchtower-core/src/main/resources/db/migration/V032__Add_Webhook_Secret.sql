-- Shared secret used to verify the HMAC signature Bitbucket sends with each webhook.
-- Nullable: an integration without a secret keeps working, and signature verification
-- switches on for that integration only once a secret is set. Encrypted at rest by
-- StringEncryptedAttributeConverter, so sized like the existing authentication column.
ALTER TABLE bb_cloud_integration_entity
    ADD COLUMN webhook_secret varchar(255) DEFAULT NULL;
