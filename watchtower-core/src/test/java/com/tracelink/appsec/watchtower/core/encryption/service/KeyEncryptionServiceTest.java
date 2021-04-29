package com.tracelink.appsec.watchtower.core.encryption.service;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.Key;
import java.security.UnrecoverableKeyException;
import java.util.Arrays;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.util.ReflectionUtils;

import com.tracelink.appsec.watchtower.core.encryption.model.EncryptionType;
import com.tracelink.appsec.watchtower.core.encryption.utils.EncryptionUtils;
import com.tracelink.appsec.watchtower.core.logging.CoreLogWatchExtension;

import ch.qos.logback.classic.Level;

@ExtendWith(SpringExtension.class)
public class KeyEncryptionServiceTest {

	@RegisterExtension
	public final CoreLogWatchExtension logWatcher =
			CoreLogWatchExtension.forClass(KeyEncryptionService.class);

	private static final String CURRENT_KEY = "currentKey";
	private static final String PREVIOUS_KEY = "previousKey";
	private static String keyStorePath;
	private static String newKeyStorePath;

	@BeforeAll
	public static void init() throws Exception {
		URL keyStoreUrl = KeyEncryptionServiceTest.class.getClassLoader()
				.getResource("encryption/keystore.p12");
		if (keyStoreUrl != null) {
			keyStorePath = Paths.get(keyStoreUrl.toURI()).toAbsolutePath().toString();
		}

		URL newKeyStoreUrl = KeyEncryptionServiceTest.class.getClassLoader()
				.getResource("encryption/new-keystore.p12");
		if (newKeyStoreUrl != null) {
			newKeyStorePath = Paths.get(newKeyStoreUrl.toURI()).toAbsolutePath().toString();
		}
	}

	@Test
	public void testInitEncryptionTypeNone() throws Exception {
		KeyEncryptionService keyEncryptionService = new KeyEncryptionService(EncryptionType.NONE,
				null, null, null, null, null, null);
		keyEncryptionService.init();

		Assertions.assertNull(getField(CURRENT_KEY, keyEncryptionService));
		Assertions.assertNull(getField(PREVIOUS_KEY, keyEncryptionService));

		Key key = EncryptionUtils.generateKey();
		Assertions.assertNull(keyEncryptionService.encryptKey(key));
		Assertions.assertNull(keyEncryptionService.decryptKey("foo"));
	}

	@Test
	public void testInitEncryptionTypeEnvironment() throws Exception {
		KeyEncryptionService keyEncryptionService = new KeyEncryptionService(
				EncryptionType.ENVIRONMENT, keyStorePath, "password", null, null, null, null);
		keyEncryptionService.init();

		Key currentKey = (Key) getField(CURRENT_KEY, keyEncryptionService);
		Assertions.assertNotNull(currentKey);
		Assertions.assertEquals("AES", currentKey.getAlgorithm());
		Assertions.assertEquals(32, currentKey.getEncoded().length);

		Assertions.assertNull(getField(PREVIOUS_KEY, keyEncryptionService));

		Assertions.assertFalse(keyEncryptionService.keyRotationInProgress());
	}

	@Test
	public void testInitEncryptionTypeEnvironmentBlankKeyStorePath() throws Exception {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> {
					KeyEncryptionService keyEncryptionService = new KeyEncryptionService(
							EncryptionType.ENVIRONMENT, " ", "password", null, null, null, null);
					keyEncryptionService.init();
				});
	}

	@Test
	public void testInitEncryptionTypeEnvironmentBlankKeyStorePassword() throws Exception {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> {
					KeyEncryptionService keyEncryptionService = new KeyEncryptionService(
							EncryptionType.ENVIRONMENT, "foo", null, null, null, null, null);
					keyEncryptionService.init();
				});
	}

	@Test
	public void testInitEncryptionTypeEnvironmentBadPassword() throws Exception {
		Assertions.assertThrows(IOException.class,
				() -> {
					KeyEncryptionService keyEncryptionService = new KeyEncryptionService(
							EncryptionType.ENVIRONMENT, keyStorePath, "foo", null, null, null,
							null);
					keyEncryptionService.init();
				});
	}

	@Test
	public void testInitEncryptionTypeEnvironmentBadAlias() throws Exception {
		Assertions.assertThrows(UnrecoverableKeyException.class,
				() -> {
					KeyEncryptionService keyEncryptionService = new KeyEncryptionService(
							EncryptionType.ENVIRONMENT, newKeyStorePath, "password", null, null,
							null, null);
					keyEncryptionService.init();
				});
	}

	@Test
	public void testInitEncryptionTypeEnvironmentWithPreviousKey() throws Exception {
		KeyEncryptionService keyEncryptionService = new KeyEncryptionService(
				EncryptionType.ENVIRONMENT, newKeyStorePath, "password", "watchtower", keyStorePath,
				"password", null);
		keyEncryptionService.init();

		Key currentKey = (Key) getField(CURRENT_KEY, keyEncryptionService);
		Assertions.assertNotNull(currentKey);
		Assertions.assertEquals("AES", currentKey.getAlgorithm());
		Assertions.assertEquals(32, currentKey.getEncoded().length);

		Key previousKey = (Key) getField(PREVIOUS_KEY, keyEncryptionService);
		Assertions.assertNotNull(previousKey);
		Assertions.assertEquals("AES", previousKey.getAlgorithm());
		Assertions.assertEquals(32, previousKey.getEncoded().length);

		Assertions.assertTrue(keyEncryptionService.keyRotationInProgress());
		keyEncryptionService.finishKeyRotation();
		Assertions.assertFalse(keyEncryptionService.keyRotationInProgress());
	}

	@Test
	public void testEncryptDecryptKey() throws Exception {
		KeyEncryptionService keyEncryptionService = new KeyEncryptionService(
				EncryptionType.ENVIRONMENT, keyStorePath, "password", null, null, null, null);
		keyEncryptionService.init();

		Key key = EncryptionUtils.generateKey();
		String encrypted = keyEncryptionService.encryptKey(key);
		Assertions.assertFalse(Arrays.equals(key.getEncoded(), encrypted.getBytes()));

		Key decrypted = keyEncryptionService.decryptKey(encrypted);
		Assertions.assertArrayEquals(key.getEncoded(), decrypted.getEncoded());
		Assertions.assertEquals(key.getAlgorithm(), decrypted.getAlgorithm());
		Assertions.assertEquals(key.getFormat(), decrypted.getFormat());
	}

	@Test
	public void testEncryptDecryptKeyNull() throws Exception {
		KeyEncryptionService keyEncryptionService = new KeyEncryptionService(
				EncryptionType.ENVIRONMENT, keyStorePath, "password", null, null, null, null);
		keyEncryptionService.init();

		Assertions.assertNull(keyEncryptionService.encryptKey(null));
		Assertions.assertNull(keyEncryptionService.decryptKey(null));
	}

	@Test
	public void testEncryptDecryptKeyNullCipher() throws Exception {
		KeyEncryptionService keyEncryptionService = new KeyEncryptionService(
				EncryptionType.ENVIRONMENT, keyStorePath, "password", null, null, null, null);
		keyEncryptionService.init();
		setField(CURRENT_KEY, keyEncryptionService, null);

		Key key = EncryptionUtils.generateKey();
		Assertions.assertEquals(new String(key.getEncoded(), StandardCharsets.UTF_8),
				keyEncryptionService.encryptKey(key));

		Assertions.assertNull(keyEncryptionService.decryptKey("foo"));

		Assertions.assertEquals(3, logWatcher.getMessages().size());
		Assertions.assertEquals(
				"Cannot initialize cipher when trying to wrap data encryption key with current key",
				logWatcher.getMessages().get(0));
		Assertions.assertEquals(
				"Cannot initialize cipher when trying to unwrap data encryption key with current key",
				logWatcher.getMessages().get(1));
		Assertions.assertEquals("Cannot unwrap data encryption key",
				logWatcher.getMessages().get(2));
	}

	@Test
	public void testDecryptKeyInvalidKey() throws Exception {
		KeyEncryptionService keyEncryptionService = new KeyEncryptionService(
				EncryptionType.ENVIRONMENT, keyStorePath, "password", null, null, null, null);
		keyEncryptionService.init();

		Key key = EncryptionUtils.generateKey();
		String encryptedKey = keyEncryptionService.encryptKey(key);

		setField(CURRENT_KEY, keyEncryptionService, EncryptionUtils.generateKey());
		Assertions.assertNull(keyEncryptionService.decryptKey(encryptedKey));

		Assertions.assertEquals(2, logWatcher.getMessages().size());
		Assertions.assertEquals(
				"Cannot unwrap data encryption key with current key",
				logWatcher.getMessages().get(0));
		Assertions.assertEquals("Cannot unwrap data encryption key",
				logWatcher.getMessages().get(1));
	}

	@Test
	public void testDecryptKeyInvalidKeyDuringRotation() throws Exception {
		logWatcher.withLevel(Level.ALL);
		KeyEncryptionService keyEncryptionService = new KeyEncryptionService(
				EncryptionType.ENVIRONMENT, keyStorePath, "password", null, null, null, null);
		keyEncryptionService.init();

		Key key = EncryptionUtils.generateKey();
		String encrypted = keyEncryptionService.encryptKey(key);
		setField(PREVIOUS_KEY, keyEncryptionService, EncryptionUtils.generateKey());
		setField("keyRotationInProgress", keyEncryptionService, true);

		Key decrypted = keyEncryptionService.decryptKey(encrypted);
		Assertions.assertArrayEquals(key.getEncoded(), decrypted.getEncoded());
		Assertions.assertEquals(key.getAlgorithm(), decrypted.getAlgorithm());
		Assertions.assertEquals(key.getFormat(), decrypted.getFormat());

		Assertions.assertFalse(logWatcher.getMessages().isEmpty());
		Assertions.assertTrue(logWatcher.getMessages().get(0)
				.contains("Cannot unwrap data encryption key with previous key"));
		Assertions.assertTrue(logWatcher.getMessages().get(1)
				.contains("Retrying decryption with current key"));
	}

	@Test
	public void testDecryptKeyPreviousKey() throws Exception {
		KeyEncryptionService keyEncryptionService = new KeyEncryptionService(
				EncryptionType.ENVIRONMENT, keyStorePath, "password", null, null, null, null);
		keyEncryptionService.init();

		Key key = EncryptionUtils.generateKey();
		String encrypted = keyEncryptionService.encryptKey(key);
		setField(PREVIOUS_KEY, keyEncryptionService, getField(CURRENT_KEY, keyEncryptionService));
		setField("keyRotationInProgress", keyEncryptionService, true);

		Key decrypted = keyEncryptionService.decryptKey(encrypted);
		Assertions.assertArrayEquals(key.getEncoded(), decrypted.getEncoded());
		Assertions.assertEquals(key.getAlgorithm(), decrypted.getAlgorithm());
		Assertions.assertEquals(key.getFormat(), decrypted.getFormat());

		Assertions.assertTrue(logWatcher.getMessages().isEmpty());
	}

	private static Object getField(String name, Object target) {
		Field field = ReflectionUtils
				.findField(KeyEncryptionService.class, name);
		if (field == null) {
			Assertions.fail("Cannot find " + name + " field");
		}
		ReflectionUtils.makeAccessible(field);
		return ReflectionUtils.getField(field, target);
	}

	private static void setField(String name, Object target, Object value) {
		Field field = ReflectionUtils
				.findField(KeyEncryptionService.class, name);
		if (field == null) {
			Assertions.fail("Cannot find " + name + " field");
		}
		ReflectionUtils.makeAccessible(field);
		ReflectionUtils.setField(field, target, value);
	}
}
