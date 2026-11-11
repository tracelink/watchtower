package com.tracelink.appsec.watchtower.core.encryption.utils;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class EncryptionUtilsTest {

	private static final byte[] PLAINTEXT = "top-secret-value".getBytes(StandardCharsets.UTF_8);
	private static final int IV_BYTES = 12;

	@Test
	public void testGenerateKeyIs256Bit() {
		Key key = EncryptionUtils.generateKey();
		Assertions.assertEquals("AES", key.getAlgorithm());
		Assertions.assertEquals(32, key.getEncoded().length);
	}

	@Test
	public void testEncryptDecryptRoundTripUsesV2Format() throws GeneralSecurityException {
		Key key = EncryptionUtils.generateKey();

		String stored = EncryptionUtils.encrypt(key, PLAINTEXT);

		Assertions.assertTrue(stored.startsWith(EncryptionUtils.V2_PREFIX));
		Assertions.assertFalse(EncryptionUtils.isLegacyFormat(stored));
		Assertions.assertArrayEquals(PLAINTEXT, EncryptionUtils.decrypt(key, stored));
	}

	@Test
	public void testEncryptSamePlaintextTwiceProducesDifferentCiphertext()
			throws GeneralSecurityException {
		Key key = EncryptionUtils.generateKey();

		Assertions.assertNotEquals(EncryptionUtils.encrypt(key, PLAINTEXT),
				EncryptionUtils.encrypt(key, PLAINTEXT));
	}

	@Test
	public void testEncryptUsesUniqueIvs() throws GeneralSecurityException {
		Key key = EncryptionUtils.generateKey();
		Set<String> ivs = new HashSet<>();
		int count = 10_000;

		for (int i = 0; i < count; i++) {
			String stored = EncryptionUtils.encrypt(key, PLAINTEXT);
			byte[] raw = Base64.getDecoder()
					.decode(stored.substring(EncryptionUtils.V2_PREFIX.length()));
			ivs.add(Base64.getEncoder().encodeToString(Arrays.copyOf(raw, IV_BYTES)));
		}

		Assertions.assertEquals(count, ivs.size());
	}

	@Test
	public void testDecryptLegacyZeroIvFormat() throws GeneralSecurityException {
		Key key = EncryptionUtils.generateKey();
		String legacy = legacyEncrypt(key, PLAINTEXT);

		Assertions.assertTrue(EncryptionUtils.isLegacyFormat(legacy));
		Assertions.assertArrayEquals(PLAINTEXT, EncryptionUtils.decrypt(key, legacy));
	}

	@Test
	public void testDecryptTamperedCiphertextFails() throws GeneralSecurityException {
		Key key = EncryptionUtils.generateKey();
		String stored = EncryptionUtils.encrypt(key, PLAINTEXT);
		byte[] raw = Base64.getDecoder()
				.decode(stored.substring(EncryptionUtils.V2_PREFIX.length()));
		raw[raw.length - 1] ^= 0x01;
		String tampered = EncryptionUtils.V2_PREFIX + Base64.getEncoder().encodeToString(raw);

		Assertions.assertThrows(GeneralSecurityException.class,
				() -> EncryptionUtils.decrypt(key, tampered));
	}

	@Test
	public void testDecryptWithWrongKeyFails() throws GeneralSecurityException {
		String stored = EncryptionUtils.encrypt(EncryptionUtils.generateKey(), PLAINTEXT);

		Assertions.assertThrows(GeneralSecurityException.class,
				() -> EncryptionUtils.decrypt(EncryptionUtils.generateKey(), stored));
	}

	@Test
	public void testDecryptMalformedInputFails() {
		Key key = EncryptionUtils.generateKey();

		Assertions.assertThrows(GeneralSecurityException.class,
				() -> EncryptionUtils.decrypt(key, EncryptionUtils.V2_PREFIX + "AAAA"));
		Assertions.assertThrows(GeneralSecurityException.class,
				() -> EncryptionUtils.decrypt(key, EncryptionUtils.V2_PREFIX + "not base64!"));
		Assertions.assertThrows(GeneralSecurityException.class,
				() -> EncryptionUtils.decrypt(key, "not base64!"));
	}

	@Test
	public void testNullKeyRejectedAsCipherInitializationFailure() {
		Assertions.assertThrows(EncryptionUtils.CipherInitializationException.class,
				() -> EncryptionUtils.encrypt(null, PLAINTEXT));
		Assertions.assertThrows(EncryptionUtils.CipherInitializationException.class,
				() -> EncryptionUtils.decrypt(null, "not base64!"));
		Assertions.assertThrows(EncryptionUtils.CipherInitializationException.class,
				() -> EncryptionUtils.wrapKey(null, EncryptionUtils.generateKey()));
		Assertions.assertThrows(EncryptionUtils.CipherInitializationException.class,
				() -> EncryptionUtils.unwrapKey(null, "not base64!", "AES"));
	}

	@Test
	public void testInvalidKeyLengthRejectedBeforeDecoding() {
		Key invalid = new SecretKeySpec("qwertyuiop".getBytes(StandardCharsets.UTF_8), "DES");

		Assertions.assertThrows(EncryptionUtils.CipherInitializationException.class,
				() -> EncryptionUtils.encrypt(invalid, PLAINTEXT));
		Assertions.assertThrows(EncryptionUtils.CipherInitializationException.class,
				() -> EncryptionUtils.decrypt(invalid, "not base64!"));
	}

	@Test
	public void testWrongKeyIsNotACipherInitializationFailure() throws GeneralSecurityException {
		String stored = EncryptionUtils.encrypt(EncryptionUtils.generateKey(), PLAINTEXT);

		GeneralSecurityException e = Assertions.assertThrows(GeneralSecurityException.class,
				() -> EncryptionUtils.decrypt(EncryptionUtils.generateKey(), stored));
		Assertions.assertFalse(e instanceof EncryptionUtils.CipherInitializationException);
	}

	@Test
	public void testWrapUnwrapKeyRoundTripUsesV2Format() throws GeneralSecurityException {
		Key kek = EncryptionUtils.generateKey();
		Key dek = EncryptionUtils.generateKey();

		String wrapped = EncryptionUtils.wrapKey(kek, dek);

		Assertions.assertTrue(wrapped.startsWith(EncryptionUtils.V2_PREFIX));
		Assertions.assertNotEquals(wrapped, EncryptionUtils.wrapKey(kek, dek));
		Assertions.assertArrayEquals(dek.getEncoded(),
				EncryptionUtils.unwrapKey(kek, wrapped, "AES").getEncoded());
	}

	@Test
	public void testUnwrapLegacyZeroIvKey() throws GeneralSecurityException {
		Key kek = EncryptionUtils.generateKey();
		Key dek = EncryptionUtils.generateKey();
		String legacy = legacyWrap(kek, dek);

		Assertions.assertArrayEquals(dek.getEncoded(),
				EncryptionUtils.unwrapKey(kek, legacy, "AES").getEncoded());
	}

	private static String legacyEncrypt(Key key, byte[] plaintext)
			throws GeneralSecurityException {
		Cipher cipher = legacyCipher(key, Cipher.ENCRYPT_MODE);
		return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext));
	}

	private static String legacyWrap(Key kek, Key dek) throws GeneralSecurityException {
		Cipher cipher = legacyCipher(kek, Cipher.WRAP_MODE);
		return Base64.getEncoder().encodeToString(cipher.wrap(dek));
	}

	private static Cipher legacyCipher(Key key, int mode) throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(mode, new SecretKeySpec(key.getEncoded(), "AES"),
				new GCMParameterSpec(128, new byte[IV_BYTES]));
		return cipher;
	}
}
