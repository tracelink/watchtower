package com.tracelink.appsec.watchtower.core.encryption.converter;

import javax.persistence.AttributeConverter;

import org.springframework.context.annotation.Lazy;

import com.tracelink.appsec.watchtower.core.encryption.service.DataEncryptionService;


/**
 * An abstract attribute converter to encrypt and decrypt entity attributes on database writes and
 * reads, respectively. This abstract converter has two methods that must be implemented by the
 * subclass: {@link AbstractEncryptedAttributeConverter#convertEntityAttributeToString(Object)} and
 * {@link AbstractEncryptedAttributeConverter#convertStringToEntityAttribute(String)}. These two
 * methods are used to convert between the entity attribute type {@code <T>} and a string. The
 * converter then delegates to the {@link DataEncryptionService} to encrypt or decrypt the string
 * representation of the attribute. This allows implementors of this class to encrypt attributes of
 * any type in the database.
 * <p>
 * During attribute conversion, this converter passes its concrete class to the
 * {@link DataEncryptionService}. This piece of information is what determines which secret key to
 * use for encryption or decryption. There is a one-to-one relationship between classes that extend
 * this abstract converter and data encryption keys stored in the database.
 *
 * @author mcool
 * @param <T> type of the entity attribute
 */
public abstract class AbstractEncryptedAttributeConverter<T> implements
		AttributeConverter<T, String> {

	private final DataEncryptionService dataEncryptionService;

	public AbstractEncryptedAttributeConverter(@Lazy DataEncryptionService dataEncryptionService) {
		this.dataEncryptionService = dataEncryptionService;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String convertToDatabaseColumn(T attribute) {
		return dataEncryptionService
				.encryptString(convertEntityAttributeToString(attribute), this.getClass());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public T convertToEntityAttribute(String dbData) {
		return convertStringToEntityAttribute(
				dataEncryptionService.decryptString(dbData, this.getClass()));
	}

	/**
	 * Convert the given entity attribute to a string representation. This string will be encrypted
	 * during a database write.
	 *
	 * @param attribute entity attribute to convert to a string
	 * @return the string to be encrypted in the database
	 */
	public abstract String convertEntityAttributeToString(T attribute);

	/**
	 * Convert the given database data to an entity attribute. This attribute will be set on an
	 * entity during a database read.
	 *
	 * @param dbData database data to convert to an entity attribute
	 * @return the attribute value to be set on an entity
	 */
	public abstract T convertStringToEntityAttribute(String dbData);
}
