package com.tracelink.appsec.watchtower.core.encryption.utils;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utilities class to handle cipher creation and secret key generation for attribute encryption.
 *
 * @author mcool
 */
public class EncryptionUtils {

	private static final Logger LOGGER = LoggerFactory.getLogger(EncryptionUtils.class);

	private static final String AES = "AES";
	private static final String ALGORITHM = "AES/GCM/NoPadding";
	private static final int KEY_SIZE = 256;
	private static final int IV_BYTE_LENGTH = 12;
	private static final int AUTHENTICATION_TAG_BIT_LENGTH = 128;

	/**
	 * Gets an AES GCM cipher for the given secret key and encryption mode. Returns null if there
	 * are errors creating the cipher.
	 *
	 * @param key            the key to create the cipher for
	 * @param encryptionMode the encryption mode for the cipher
	 * @return the initialized cipher, or null if there is an error
	 */
	public static Cipher getCipherForKeyAndMode(Key key, int encryptionMode) {
		if (key == null) {
			return null;
		}
		// Attempt to create cipher from given key and mode
		try {
			Cipher cipher = Cipher.getInstance(ALGORITHM);
			SecretKey secretKey = new SecretKeySpec(key.getEncoded(), AES);

			byte[] ivBytes = new byte[IV_BYTE_LENGTH];
			AlgorithmParameterSpec algorithmParameters = new GCMParameterSpec(
					AUTHENTICATION_TAG_BIT_LENGTH, ivBytes);

			cipher.init(encryptionMode, secretKey, algorithmParameters);
			return cipher;
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException e) {
			LOGGER.warn("Cannot initialize cipher for key: " + e.getMessage());
		}
		return null;
	}

	/**
	 * Generates an AES secret key to be used for attribute encryption.
	 *
	 * @return the generated key
	 */
	public static Key generateKey() {
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
			keyGenerator.init(KEY_SIZE);
			keyGenerator.init(new SecureRandom());
			return keyGenerator.generateKey();
		} catch (NoSuchAlgorithmException e) {
			LOGGER.warn("Cannot generate AES key: " + e.getMessage());
		}
		return null;
	}
}
