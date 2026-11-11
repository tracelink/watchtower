package com.tracelink.appsec.watchtower.core.encryption.utils;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utilities class to handle AES-GCM encryption, key wrapping and secret key generation for
 * attribute encryption.
 * <p>
 * Values are stored as {@value #V2_PREFIX} followed by Base64(IV || ciphertext || tag), with a
 * fresh random 96-bit IV per operation. Values without the prefix are the legacy format
 * (Base64(ciphertext || tag) encrypted with an all-zero IV); they can still be decrypted so that
 * existing data keeps working until it is re-encrypted by a key rotation. Base64 never contains
 * {@code ':'}, so the prefix cannot collide with legacy data.
 *
 * @author mcool
 */
public final class EncryptionUtils {

	private static final Logger LOGGER = LoggerFactory.getLogger(EncryptionUtils.class);

	/**
	 * Prefix identifying values encrypted with a random IV.
	 */
	public static final String V2_PREFIX = "v2:";

	private static final String AES = "AES";
	private static final String ALGORITHM = "AES/GCM/NoPadding";
	private static final int KEY_SIZE = 256;
	private static final int IV_BYTE_LENGTH = 12;
	private static final int AUTHENTICATION_TAG_BIT_LENGTH = 128;
	private static final int AUTHENTICATION_TAG_BYTE_LENGTH = AUTHENTICATION_TAG_BIT_LENGTH / 8;
	private static final byte[] LEGACY_IV = new byte[IV_BYTE_LENGTH];
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	private EncryptionUtils() {
	}

	/**
	 * Encrypts the given plaintext with a fresh random IV.
	 *
	 * @param key       the AES key
	 * @param plaintext the bytes to encrypt
	 * @return the stored representation, {@value #V2_PREFIX} + Base64(IV || ciphertext || tag)
	 * @throws GeneralSecurityException if the key is null or encryption fails
	 */
	public static String encrypt(Key key, byte[] plaintext) throws GeneralSecurityException {
		requireValidKey(key);
		byte[] iv = newIv();
		Cipher cipher = initCipher(key, Cipher.ENCRYPT_MODE, iv);
		return encodeV2(iv, cipher.doFinal(plaintext));
	}

	/**
	 * Decrypts a value produced by {@link #encrypt(Key, byte[])} or by the legacy zero-IV format.
	 *
	 * @param key    the AES key
	 * @param stored the stored representation
	 * @return the decrypted bytes
	 * @throws GeneralSecurityException if the key is null, the input is malformed, or
	 *                                  authentication fails
	 */
	public static byte[] decrypt(Key key, String stored) throws GeneralSecurityException {
		requireValidKey(key);
		EncodedValue value = decode(stored);
		return initCipher(key, Cipher.DECRYPT_MODE, value.iv()).doFinal(value.body());
	}

	/**
	 * Wraps (encrypts) the given key with the key encryption key, using a fresh random IV.
	 *
	 * @param keyEncryptionKey the wrapping key
	 * @param keyToWrap        the key to wrap
	 * @return the stored representation, {@value #V2_PREFIX} + Base64(IV || wrapped key || tag)
	 * @throws GeneralSecurityException if either key is null or wrapping fails
	 */
	public static String wrapKey(Key keyEncryptionKey, Key keyToWrap)
			throws GeneralSecurityException {
		requireValidKey(keyEncryptionKey);
		if (keyToWrap == null) {
			throw new GeneralSecurityException("Key to wrap must not be null");
		}
		byte[] iv = newIv();
		Cipher cipher = initCipher(keyEncryptionKey, Cipher.WRAP_MODE, iv);
		return encodeV2(iv, cipher.wrap(keyToWrap));
	}

	/**
	 * Unwraps a key produced by {@link #wrapKey(Key, Key)} or by the legacy zero-IV format.
	 *
	 * @param keyEncryptionKey the wrapping key
	 * @param stored           the stored representation
	 * @param wrappedAlgorithm the algorithm of the wrapped key
	 * @return the unwrapped secret key
	 * @throws GeneralSecurityException if the key is null, the input is malformed, or
	 *                                  authentication fails
	 */
	public static Key unwrapKey(Key keyEncryptionKey, String stored, String wrappedAlgorithm)
			throws GeneralSecurityException {
		requireValidKey(keyEncryptionKey);
		EncodedValue value = decode(stored);
		Cipher cipher = initCipher(keyEncryptionKey, Cipher.UNWRAP_MODE, value.iv());
		return cipher.unwrap(value.body(), wrappedAlgorithm, Cipher.SECRET_KEY);
	}

	/**
	 * Determines whether a stored value uses the legacy zero-IV format and should be re-encrypted.
	 *
	 * @param stored the stored representation
	 * @return true if the value is non-null and not in the {@value #V2_PREFIX} format
	 */
	public static boolean isLegacyFormat(String stored) {
		return stored != null && !stored.startsWith(V2_PREFIX);
	}

	/**
	 * Generates a 256-bit AES secret key to be used for attribute encryption.
	 *
	 * @return the generated key, or null if AES is unavailable
	 */
	public static Key generateKey() {
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
			keyGenerator.init(KEY_SIZE, SECURE_RANDOM);
			return keyGenerator.generateKey();
		} catch (NoSuchAlgorithmException e) {
			LOGGER.warn("Cannot generate AES key: " + e.getMessage());
		}
		return null;
	}

	private static void requireValidKey(Key key) throws CipherInitializationException {
		if (key == null || key.getEncoded() == null) {
			throw new CipherInitializationException("Key must not be null", null);
		}
		int length = key.getEncoded().length;
		if (length != 16 && length != 24 && length != 32) {
			throw new CipherInitializationException("Invalid AES key length: " + length, null);
		}
	}

	private static Cipher initCipher(Key key, int mode, byte[] iv)
			throws CipherInitializationException {
		try {
			Cipher cipher = Cipher.getInstance(ALGORITHM);
			cipher.init(mode, new SecretKeySpec(key.getEncoded(), AES),
					new GCMParameterSpec(AUTHENTICATION_TAG_BIT_LENGTH, iv));
			return cipher;
		} catch (GeneralSecurityException e) {
			throw new CipherInitializationException("Cannot initialize cipher", e);
		}
	}

	private static byte[] newIv() {
		byte[] iv = new byte[IV_BYTE_LENGTH];
		SECURE_RANDOM.nextBytes(iv);
		return iv;
	}

	private static String encodeV2(byte[] iv, byte[] body) {
		byte[] combined = ByteBuffer.allocate(iv.length + body.length).put(iv).put(body).array();
		return V2_PREFIX + Base64.getEncoder().encodeToString(combined);
	}

	private static EncodedValue decode(String stored) throws GeneralSecurityException {
		if (stored == null) {
			throw new GeneralSecurityException("Encrypted value must not be null");
		}
		if (isLegacyFormat(stored)) {
			return new EncodedValue(LEGACY_IV, base64Decode(stored));
		}
		byte[] raw = base64Decode(stored.substring(V2_PREFIX.length()));
		if (raw.length < IV_BYTE_LENGTH + AUTHENTICATION_TAG_BYTE_LENGTH) {
			throw new GeneralSecurityException("Encrypted value is too short");
		}
		return new EncodedValue(Arrays.copyOfRange(raw, 0, IV_BYTE_LENGTH),
				Arrays.copyOfRange(raw, IV_BYTE_LENGTH, raw.length));
	}

	private static byte[] base64Decode(String encoded) throws GeneralSecurityException {
		try {
			return Base64.getDecoder().decode(encoded);
		} catch (IllegalArgumentException e) {
			throw new GeneralSecurityException("Encrypted value is not valid Base64", e);
		}
	}

	private record EncodedValue(byte[] iv, byte[] body) {
	}

	/**
	 * Thrown when a cipher cannot be created for a key (missing or invalid key, unavailable
	 * algorithm), as opposed to the encryption operation itself failing.
	 */
	public static final class CipherInitializationException extends GeneralSecurityException {

		private static final long serialVersionUID = 1L;

		CipherInitializationException(String message, Throwable cause) {
			super(message, cause);
		}
	}
}
