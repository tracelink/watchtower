package com.tracelink.appsec.watchtower.core.encryption.converter;

import com.tracelink.appsec.watchtower.core.encryption.service.DataEncryptionService;
import org.springframework.context.annotation.Lazy;

/**
 * An attribute converter to encrypt and decrypt strings on database writes and reads,
 * respectively. This is an implementation of the {@link AbstractEncryptedAttributeConverter} that
 * simply returns the entity attribute or the database data as is without performing any additional
 * transformations.
 * <p>
 * This converter can be used on its own, or it can be extended. The benefit of extending this
 * class is that you can have separate encryption keys for specific entities or pieces of data. In
 * general, each subclass that implements the {@link AbstractEncryptedAttributeConverter}
 * corresponds to a single data encryption key.
 *
 * @author mcool
 */
public class StringEncryptedAttributeConverter extends
		AbstractEncryptedAttributeConverter<String> {

	public StringEncryptedAttributeConverter(@Lazy DataEncryptionService dataEncryptionService) {
		super(dataEncryptionService);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String convertEntityAttributeToString(String attribute) {
		return attribute;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String convertStringToEntityAttribute(String dbData) {
		return dbData;
	}
}
