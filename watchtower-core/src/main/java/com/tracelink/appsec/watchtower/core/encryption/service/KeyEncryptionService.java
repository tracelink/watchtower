package com.tracelink.appsec.watchtower.core.encryption.service;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Base64;

import javax.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.encryption.model.EncryptionType;
import com.tracelink.appsec.watchtower.core.encryption.utils.EncryptionUtils;

/**
 * Service to handle encryption and decryption of data encryption keys. Loads and stores current and
 * previous key encryption keys, if configured.
 *
 * @author mcool
 */
@Service
public class KeyEncryptionService {

	private static final Logger LOGGER = LoggerFactory.getLogger(KeyEncryptionService.class);
	private static final String WRAPPED_KEY_ALGORITHM = "AES";
	private static final String PKCS12 = "PKCS12";
	private static final String LOAD_KEY_FAIL =
			"Could not load key from keystore. Please check that the keystore password and key alias are correct: ";
	private static final String UNKNOWN_ENC_TYPE = "Unknown encryption type: ";
	private static final String NULL_CIPHER_WRAP =
			"Cannot initialize cipher when trying to wrap data encryption key";
	private static final String CANNOT_WRAP = "Cannot wrap data encryption key";
	private static final String NULL_CIPHER_UNWRAP =
			"Cannot initialize cipher when trying to unwrap data encryption key";
	private static final String CANNOT_UNWRAP = "Cannot unwrap data encryption key";
	private static final String W_CURRENT_KEY = " with current key";
	private static final String W_PREVIOUS_KEY = " with previous key";
	private static final String RETRY_DECRYPT = "Retrying decryption";

	private final EncryptionType encryptionType;
	private final String currentKeyStorePath;
	private final String currentKeyStorePassword;
	private final String currentKeyAlias;
	private final String previousKeyStorePath;
	private final String previousKeyStorePassword;
	private final String previousKeyAlias;

	private Key currentKey;
	private Key previousKey;
	private boolean keyRotationInProgress = false;

	public KeyEncryptionService(
			@Value("${watchtower.encryption.type:none}") EncryptionType encryptionType,
			@Value("${watchtower.encryption.environment.currentKeyStorePath:#{null}}") String currentKeyStorePath,
			@Value("${watchtower.encryption.environment.currentKeyStorePassword:#{null}}") String currentKeyStorePassword,
			@Value("${watchtower.encryption.environment.currentKeyAlias:#{null}}") String currentKeyAlias,
			@Value("${watchtower.encryption.environment.previousKeyStorePath:#{null}}") String previousKeyStorePath,
			@Value("${watchtower.encryption.environment.previousKeyStorePassword:#{null}}") String previousKeyStorePassword,
			@Value("${watchtower.encryption.environment.previousKeyAlias:#{null}}") String previousKeyAlias) {
		this.encryptionType = encryptionType;
		this.currentKeyStorePath = currentKeyStorePath;
		this.currentKeyStorePassword = currentKeyStorePassword;
		this.currentKeyAlias = currentKeyAlias;
		this.previousKeyStorePath = previousKeyStorePath;
		this.previousKeyStorePassword = previousKeyStorePassword;
		this.previousKeyAlias = previousKeyAlias;
	}

	/**
	 * Initializes environment variable keys, if configured.
	 *
	 * @throws IllegalArgumentException if an unknown encryption type is provided
	 * @throws Exception                if an error occurs while loading a key from a KeyStore
	 */
	@PostConstruct
	public void init() throws IllegalArgumentException, Exception {
		switch (encryptionType) {
			case ENVIRONMENT:
				initializeEnvironmentVariableKeys();
				break;
			case NONE:
				break;
			default:
				throw new IllegalArgumentException(UNKNOWN_ENC_TYPE + encryptionType);
		}
	}

	/*
	 * Encryption and decryption methods
	 */

	/**
	 * Encrypts the given key using the {@code currentKey} stored in this class. There is no
	 * scenario where this method will attempt to encrypt the key using the {@code previousKey}.
	 * <p>
	 * If the key cannot be encrypted for some reason, this method will return a Base64-encoded
	 * string containing the contents of the key. Any encryption failures will be logged as an
	 * indication that something may be wrong.
	 * <p>
	 * The strategy for this method allows for recovery from catastrophic key losses. Data
	 * encryption keys can be overwritten with new values and will be encrypted with whichever key
	 * is the {@code currentKey} at that time.
	 *
	 * @param attribute the data encryption key to be wrapped
	 * @return the wrapped data encryption key, or null if Watchtower is configured with
	 *         {@link EncryptionType#NONE}.
	 */
	public String encryptKey(Key attribute) {
		// If attribute is null or Watchtower is not configured to handle encryption, return null
		if (attribute == null || encryptionType.equals(EncryptionType.NONE)) {
			return null;
		}
		// Get a cipher for the current key in wrap mode
		Cipher cipher = EncryptionUtils.getCipherForKeyAndMode(currentKey, Cipher.WRAP_MODE);
		if (cipher == null) {
			LOGGER.warn(NULL_CIPHER_WRAP + W_CURRENT_KEY);
			return new String(attribute.getEncoded(), StandardCharsets.UTF_8);
		}
		// Try to wrap the key using the cipher and log any errors
		try {
			byte[] wrapped = cipher.wrap(attribute);
			return Base64.getEncoder().encodeToString(wrapped);
		} catch (IllegalArgumentException | IllegalStateException | IllegalBlockSizeException
				| InvalidKeyException | UnsupportedOperationException e) {
			LOGGER.error(CANNOT_WRAP + W_CURRENT_KEY, e);
		}
		return Base64.getEncoder().encodeToString(attribute.getEncoded());
	}

	/**
	 * Decrypts the given key. If the key encryption keys are being rotated, this method will first
	 * attempt to decrypt with the {@code previousKey}, otherwise it will use the {@code
	 * currentKey}. If decryption with the previous key fails for any reason, it will then attempt
	 * to decrypt using the current key. This helps to ensure that Watchtower can recover if the
	 * server goes down in the middle of a key encryption key rotation.
	 * <p>
	 * If decryption with the {@code previousKey} and/or {@code currentKey} fails, this method will
	 * return a key containing the indecipherable data. Any decryption failures will be logged as an
	 * indication that something may be wrong.
	 *
	 * @param dbData the data encryption key to be unwrapped
	 * @return the decrypted database data, or null
	 */
	public Key decryptKey(String dbData) {
		// If dbData is null or Watchtower is not configured to handle encryption, return null
		if (dbData == null || encryptionType.equals(EncryptionType.NONE)) {
			return null;
		}
		// If key rotation is in progress, decrypt using the previous key
		if (keyRotationInProgress) {
			Key decrypted = decryptKeyWithKey(dbData, previousKey, false);
			if (decrypted != null) {
				return decrypted;
			} else {
				LOGGER.info(RETRY_DECRYPT + W_CURRENT_KEY);
			}
		}
		Key decrypted = decryptKeyWithKey(dbData, currentKey, true);
		if (decrypted != null) {
			return decrypted;
		} else {
			LOGGER.error(CANNOT_UNWRAP);
			return null;
		}
	}

	/**
	 * Decrypts the given key using the given decryption key. The given boolean current is used to
	 * indicate whether the {@code currentKey} or {@code previousKey} is being used for decryption.
	 * Returns null if an error occurs when creating the cipher or decrypting the key.
	 *
	 * @param dbData  the data encryption key to be unwrapped
	 * @param current boolean indicating whether the {@code currentKey} or {@code previousKey} is
	 *                being used
	 * @return the decrypted database data, or null if Watchtower is configured with
	 *         {@link EncryptionType#NONE}
	 */
	private Key decryptKeyWithKey(String dbData, Key decryptionKey, boolean current) {
		// Get a cipher for the decryption key in unwrap mode
		Cipher cipher = EncryptionUtils.getCipherForKeyAndMode(decryptionKey, Cipher.UNWRAP_MODE);
		if (cipher == null) {
			LOGGER.warn(NULL_CIPHER_UNWRAP + (current ? W_CURRENT_KEY : W_PREVIOUS_KEY));
			return null;
		}
		// Try to unwrap the key using the cipher and log any errors
		try {
			byte[] wrapped = Base64.getDecoder().decode(dbData);
			return cipher.unwrap(wrapped, WRAPPED_KEY_ALGORITHM, Cipher.SECRET_KEY);
		} catch (IllegalArgumentException | IllegalStateException | NoSuchAlgorithmException
				| InvalidKeyException | UnsupportedOperationException e) {
			String message = CANNOT_UNWRAP + (current ? W_CURRENT_KEY : W_PREVIOUS_KEY);
			if (current) {
				LOGGER.error(message, e);
			} else {
				LOGGER.warn(message, e);
			}
		}
		return null;
	}

	/*
	 * Status methods
	 */

	/**
	 * Determines whether a key encryption key rotation is in progress.
	 *
	 * @return true if rotation is in progress, false otherwise
	 */
	public boolean keyRotationInProgress() {
		return keyRotationInProgress;
	}

	/**
	 * Updates the status of the key encryption key rotation to indicate the rotation is complete.
	 */
	public void finishKeyRotation() {
		this.keyRotationInProgress = false;
	}

	/*
	 * Post Construct methods
	 */

	/**
	 * Initializes the {@code currentKey} and {@code previousKey} from environment variables, if
	 * provided. This method is only called when {@link EncryptionType#ENVIRONMENT} is configured. A
	 * current key is required, but a previous key is not.
	 *
	 * @throws IllegalArgumentException if a path to the current keystore and a password are not
	 *                                  provided
	 * @throws Exception                if there is an error trying to load a key from the keystore
	 */
	private void initializeEnvironmentVariableKeys() throws Exception {
		// Make sure a current key has been provided
		if (StringUtils.isBlank(currentKeyStorePath) || StringUtils
				.isBlank(currentKeyStorePassword)) {
			throw new IllegalArgumentException(
					"Must provide a path to the keystore and a password");
		}
		// Set up the current key
		this.currentKey = loadKey(currentKeyStorePath, currentKeyStorePassword, currentKeyAlias);
		// Set up the previous key, if provided
		if (!StringUtils.isBlank(previousKeyStorePath) && !StringUtils.isBlank(
				previousKeyStorePassword)) {
			this.previousKey = loadKey(previousKeyStorePath, previousKeyStorePassword,
					previousKeyAlias);
		}
		// If previous key has been initialized, prepare for key rotation
		if (previousKey != null) {
			keyRotationInProgress = true;
		}
	}

	/**
	 * Loads a key from a keystore located at the given path. Uses the keystore password and key
	 * alias to access the key inside. The keystore should be in PKCS12 format.
	 *
	 * @param keyStorePath     path to the keystore
	 * @param keyStorePassword password for the keystore
	 * @param keyAlias         alias for the key within the keystore
	 * @return the key loaded from the keystore
	 * @throws IOException               if there is an error loading the file or the keystore
	 * @throws KeyStoreException         if there is an error getting the keystore instance or
	 *                                   getting the key from the keystore
	 * @throws NoSuchAlgorithmException  if the algorithm used to check the integrity of the
	 *                                   keystore cannot be found
	 * @throws CertificateException      if certificates in the keystore cannot be loaded
	 * @throws UnrecoverableKeyException if the key cannot be recovered (e.g. wrong password)
	 */
	private Key loadKey(String keyStorePath, String keyStorePassword, String keyAlias)
			throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException,
			UnrecoverableKeyException {
		Key key;
		try (FileInputStream is = new FileInputStream(keyStorePath)) {
			KeyStore ks = KeyStore.getInstance(PKCS12);
			ks.load(is, keyStorePassword.toCharArray());
			if (StringUtils.isBlank(keyAlias)) {
				keyAlias = "mykey"; // Use default key alias
			}
			key = ks.getKey(keyAlias, keyStorePassword.toCharArray());
		}
		if (key == null) {
			throw new UnrecoverableKeyException(LOAD_KEY_FAIL + keyStorePath);
		}
		return key;
	}
}
