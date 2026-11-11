package com.tracelink.appsec.watchtower.core.encryption.converter;

import org.springframework.context.annotation.Lazy;

import com.tracelink.appsec.watchtower.core.encryption.service.DataEncryptionService;

/**
 * Encrypts alert channel webhook URLs, which embed the channel's key and token, under their own
 * data encryption key. Key rotation re-encrypts them like every other encrypted column.
 *
 * @author Watchtower
 */
public class AlertWebhookEncryptedConverter extends StringEncryptedAttributeConverter {

	public AlertWebhookEncryptedConverter(@Lazy DataEncryptionService dataEncryptionService) {
		super(dataEncryptionService);
	}
}
