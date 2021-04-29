package com.tracelink.appsec.watchtower.core.encryption.service;

import com.tracelink.appsec.watchtower.core.encryption.model.DataEncryptionKey;
import com.tracelink.appsec.watchtower.core.encryption.model.EncryptionType;
import com.tracelink.appsec.watchtower.core.encryption.repository.DataEncryptionKeyRepository;
import com.tracelink.appsec.watchtower.core.encryption.utils.EncryptionUtils;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Optional;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Service to handle encryption and decryption of database attributes. Interacts with the {@link
 * DataEncryptionKeyRepository} to access the data encryption keys stored in the database.
 *
 * @author mcool
 */
@Service
public class DataEncryptionService {

	private static final Logger LOGGER = LoggerFactory.getLogger(DataEncryptionService.class);
	private static final String NO_DEK_FOUND = "No data encryption key found for converter ";
	private static final String NULL_CIPHER_ENCRYPT = "Cannot initialize cipher when trying to encrypt with converter ";
	private static final String CANNOT_ENCRYPT = "Cannot encrypt entity attribute with converter ";
	private static final String NULL_KEY_DECRYPT = "Skipping decryption with null key";
	private static final String NULL_CIPHER_DECRYPT = "Cannot initialize cipher when trying to decrypt with converter ";
	private static final String CANNOT_DECRYPT = "Cannot decrypt database column with converter ";
	private static final String RETRY_DECRYPT = "Retrying decryption with current key for converter ";
	private static final String W_CURRENT_KEY = " with current key";
	private static final String W_PREVIOUS_KEY = " with previous key";

	private final EncryptionType encryptionType;
	private final DataEncryptionKeyRepository dataEncryptionKeyRepository;

	public DataEncryptionService(
			@Value("${watchtower.encryption.type:none}") EncryptionType encryptionType,
			@Autowired DataEncryptionKeyRepository dataEncryptionKeyRepository) {
		this.encryptionType = encryptionType;
		this.dataEncryptionKeyRepository = dataEncryptionKeyRepository;
	}

	/**
	 * Encrypts the given entity attribute using the current key stored in the {@link
	 * DataEncryptionKey} associated with the given converter class. There is no scenario where
	 * this method will attempt to encrypt the attribute using a previous key. If Watchtower is
	 * configured with {@link EncryptionType#NONE}, or if the attribute cannot be encrypted, this
	 * method will return the given attribute unchanged.
	 * <p>
	 * The strategy for this method allows for recovery from catastrophic data losses. Data can be
	 * overwritten with new values and will be encrypted with whichever key is the current key at
	 * that time.
	 *
	 * @param attribute      the entity attribute to be encrypted
	 * @param converterClass the attribute converter class used to identify the appropriate {@link
	 *                       DataEncryptionKey}
	 * @return the encrypted attribute, or null if Watchtower is configured with {@link
	 * EncryptionType#NONE}. If the attribute cannot be encrypted, returns the given value
	 * unchanged.
	 */
	public String encryptString(String attribute, Class<?> converterClass) {
		// If attribute is null or Watchtower is not configured to handle encryption, return attribute
		if (attribute == null || encryptionType.equals(EncryptionType.NONE)) {
			return attribute;
		}
		// Get the data encryption key for the given converter class
		Optional<DataEncryptionKey> dataEncryptionKey = dataEncryptionKeyRepository
				.findByConverterClassName(converterClass.getName());
		if (!dataEncryptionKey.isPresent()) {
			LOGGER.warn(NO_DEK_FOUND + converterClass.getName());
			return attribute;
		}
		// If the current key is null, return attribute
		Key encryptionKey = dataEncryptionKey.get().getCurrentKey();
		if (encryptionKey == null) {
			return attribute;
		}
		// Get a cipher for the encryption key in encrypt mode
		Cipher cipher = EncryptionUtils.getCipherForKeyAndMode(encryptionKey, Cipher.ENCRYPT_MODE);
		if (cipher == null) {
			LOGGER.warn(NULL_CIPHER_ENCRYPT + converterClass.getName());
			return attribute;
		}
		// Try to encrypt the attribute using the cipher and log any errors
		try {
			byte[] encrypted = cipher.doFinal(attribute.getBytes());
			return Base64.getEncoder().encodeToString(encrypted);
		} catch (IllegalArgumentException | IllegalStateException | IllegalBlockSizeException
				| BadPaddingException e) {
			LOGGER.error(CANNOT_ENCRYPT + converterClass.getName(), e);
		}
		return attribute;
	}

	/**
	 * Decrypts the given database data using the {@link DataEncryptionKey} associated with the
	 * given converter class. If the {@link DataEncryptionKey} is in the middle of a key rotation,
	 * this method will first attempt to decrypt with the previous key, otherwise it will use the
	 * current key. If decryption with the previous key fails for any reason, it will then attempt
	 * to decrypt using the current key. This helps to ensure that Watchtower can recover if the
	 * server goes down in the middle of a data encryption key rotation.
	 * <p>
	 * If decryption with the previous and/or current key fails, and the data encryption key is in
	 * the middle of a key rotation, this method will return the database data unchanged.
	 * Otherwise, an exception will be thrown. Any decryption failures with the previous or current
	 * key will be logged.
	 *
	 * @param dbData         the database data to be decrypted
	 * @param converterClass the attribute converter class used to identify the appropriate {@link
	 *                       DataEncryptionKey}
	 * @return the decrypted database data, or null if Watchtower is configured with {@link
	 * EncryptionType#NONE}. If the database data cannot be decrypted, returns the given value
	 * unchanged.
	 */
	public String decryptString(String dbData, Class<?> converterClass) {
		// If dbData is null or Watchtower is not configured to handle encryption, return dbData
		if (dbData == null || encryptionType.equals(EncryptionType.NONE)) {
			return dbData;
		}
		// Get the data encryption key for the given converter class
		Optional<DataEncryptionKey> optionalDataEncryptionKey = dataEncryptionKeyRepository
				.findByConverterClassName(converterClass.getName());
		if (!optionalDataEncryptionKey.isPresent()) {
			LOGGER.warn(NO_DEK_FOUND + converterClass.getName());
			return dbData;
		}
		DataEncryptionKey dataEncryptionKey = optionalDataEncryptionKey.get();
		// If key rotation is in progress, use previous key to decrypt
		if (dataEncryptionKey.isRotationInProgress()) {
			String decrypted = decryptStringWithKey(dbData, dataEncryptionKey, false);
			if (decrypted != null) {
				return decrypted;
			} else {
				LOGGER.info(RETRY_DECRYPT + converterClass.getName());
			}
		}
		// Use current key to decrypt
		String decrypted = decryptStringWithKey(dbData, dataEncryptionKey, true);
		if (decrypted != null) {
			return decrypted;
		}
		// If the data encryption key is being rotated, assume dbData is already decrypted
		// If the data encryption key is disabled, assume dbData is already decrypted
		if (!dataEncryptionKey.isRotationInProgress() && !dataEncryptionKey.isDisabled()) {
			// The keys are in a bad state and this service cannot decrypt
			LOGGER.error(CANNOT_DECRYPT + converterClass.getName());
		}
		return dbData;
	}


	/**
	 * Decrypts the given database data using the given {@link DataEncryptionKey}. The given
	 * boolean current is used to indicate whether the current or previous key should be used for
	 * decryption.
	 *
	 * @param dbData            the database data to be decrypted
	 * @param dataEncryptionKey the {@link DataEncryptionKey} to use for decryption
	 * @param current           boolean indicating whether the current or previous key should be
	 *                          used
	 * @return the decrypted database data, or null if decryption is unsuccessful for any reason
	 */
	private String decryptStringWithKey(String dbData, DataEncryptionKey dataEncryptionKey,
			boolean current) {
		Key decryptionKey =
				current ? dataEncryptionKey.getCurrentKey() : dataEncryptionKey.getPreviousKey();
		// If decryption key is null, return null
		if (decryptionKey == null) {
			LOGGER.info(NULL_KEY_DECRYPT);
			return null;
		}
		// Get a cipher for the decryption key in decrypt mode
		Cipher cipher = EncryptionUtils.getCipherForKeyAndMode(decryptionKey, Cipher.DECRYPT_MODE);
		if (cipher == null) {
			LOGGER.warn(NULL_CIPHER_DECRYPT + dataEncryptionKey.getConverterClassName());
			return null;
		}
		// Try to decrypt the dbData using the cipher and log any errors
		try {
			// Get a cipher for the decryption key in decrypt mode
			EncryptionUtils.getCipherForKeyAndMode(decryptionKey, Cipher.DECRYPT_MODE);
			// Try to decrypt the dbData using the cipher and log any errors
			byte[] encrypted = Base64.getDecoder().decode(dbData);
			return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
		} catch (IllegalArgumentException | IllegalStateException | IllegalBlockSizeException | BadPaddingException e) {
			String message = CANNOT_DECRYPT + dataEncryptionKey.getConverterClassName()
					+ (current ? W_CURRENT_KEY : W_PREVIOUS_KEY);
			if (dataEncryptionKey.isRotationInProgress()) {
				LOGGER.warn(message, e);
			} else {
				LOGGER.error(message, e);
			}
		}
		return null;
	}
}
