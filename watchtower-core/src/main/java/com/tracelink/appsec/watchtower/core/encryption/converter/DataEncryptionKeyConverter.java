package com.tracelink.appsec.watchtower.core.encryption.converter;

import com.tracelink.appsec.watchtower.core.encryption.service.KeyEncryptionService;
import java.security.Key;
import javax.persistence.AttributeConverter;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * An attribute converter to encrypt or decrypt data encryption keys on database writes or reads,
 * respectively. Delegates to the {@link KeyEncryptionService} to encrypt and decrypt keys.
 *
 * @author mcool
 */
public class DataEncryptionKeyConverter implements AttributeConverter<Key, String> {

	private final KeyEncryptionService keyEncryptionService;

	public DataEncryptionKeyConverter(@Autowired KeyEncryptionService keyEncryptionService) {
		this.keyEncryptionService = keyEncryptionService;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String convertToDatabaseColumn(Key attribute) {
		return keyEncryptionService.encryptKey(attribute);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Key convertToEntityAttribute(String dbData) {
		return keyEncryptionService.decryptKey(dbData);
	}
}
