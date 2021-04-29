package com.tracelink.appsec.watchtower.core.encryption.service;

import java.security.Key;
import java.util.Optional;

import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.BDDMockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.encryption.model.DataEncryptionKey;
import com.tracelink.appsec.watchtower.core.encryption.model.EncryptionType;
import com.tracelink.appsec.watchtower.core.encryption.repository.DataEncryptionKeyRepository;
import com.tracelink.appsec.watchtower.core.encryption.utils.EncryptionUtils;
import com.tracelink.appsec.watchtower.core.logging.CoreLogWatchExtension;

import ch.qos.logback.classic.Level;

@ExtendWith(SpringExtension.class)
public class DataEncryptionServiceTest {

	@RegisterExtension
	public final CoreLogWatchExtension logWatcher =
			CoreLogWatchExtension.forClass(DataEncryptionService.class);

	@MockBean
	private DataEncryptionKeyRepository dataEncryptionKeyRepository;

	@Test
	public void testEncryptDecryptString() {
		DataEncryptionService dataEncryptionService = new DataEncryptionService(
				EncryptionType.ENVIRONMENT, dataEncryptionKeyRepository);

		DataEncryptionKey dataEncryptionKey = new DataEncryptionKey();
		dataEncryptionKey.setCurrentKey(EncryptionUtils.generateKey());
		dataEncryptionKey.setConverterClassName(TestConverter.class.getName());
		BDDMockito.when(dataEncryptionKeyRepository
				.findByConverterClassName(TestConverter.class.getName())).thenReturn(
						Optional.of(dataEncryptionKey));

		String encrypted = dataEncryptionService.encryptString("foo", TestConverter.class);
		Assertions.assertNotEquals("foo", encrypted);
		Assertions.assertEquals("foo",
				dataEncryptionService.decryptString(encrypted, TestConverter.class));
	}

	@Test
	public void testEncryptDecryptStringNullAttribute() {
		DataEncryptionService dataEncryptionService = new DataEncryptionService(
				EncryptionType.ENVIRONMENT, dataEncryptionKeyRepository);

		Assertions.assertNull(dataEncryptionService.encryptString(null, TestConverter.class));
		Assertions.assertNull(dataEncryptionService.decryptString(null, TestConverter.class));
	}

	@Test
	public void testEncryptDecryptStringEncryptionTypeNone() {
		DataEncryptionService dataEncryptionService = new DataEncryptionService(
				EncryptionType.NONE, dataEncryptionKeyRepository);

		Assertions.assertEquals("foo",
				dataEncryptionService.encryptString("foo", TestConverter.class));
		Assertions.assertEquals("bar",
				dataEncryptionService.decryptString("bar", TestConverter.class));
	}

	@Test
	public void testEncryptDecryptStringDekNotFound() {
		logWatcher.withLevel(Level.ALL);
		DataEncryptionService dataEncryptionService = new DataEncryptionService(
				EncryptionType.ENVIRONMENT, dataEncryptionKeyRepository);

		BDDMockito.when(dataEncryptionKeyRepository
				.findByConverterClassName(TestConverter.class.getName()))
				.thenReturn(Optional.empty());

		Assertions.assertEquals("foo",
				dataEncryptionService.encryptString("foo", TestConverter.class));
		Assertions.assertEquals("foo",
				dataEncryptionService.decryptString("foo", TestConverter.class));

		Assertions.assertEquals(2, logWatcher.getMessages().size());
		Assertions.assertEquals("No data encryption key found for converter "
				+ TestConverter.class.getName(), logWatcher.getMessages().get(0));
		Assertions.assertEquals("No data encryption key found for converter "
				+ TestConverter.class.getName(), logWatcher.getMessages().get(1));
	}

	@Test
	public void testEncryptDecryptStringNullCipher() {
		DataEncryptionService dataEncryptionService = new DataEncryptionService(
				EncryptionType.ENVIRONMENT, dataEncryptionKeyRepository);

		DataEncryptionKey dataEncryptionKey = new DataEncryptionKey();
		dataEncryptionKey.setConverterClassName(TestConverter.class.getName());
		dataEncryptionKey.setCurrentKey(new SecretKeySpec("qwertyuiop".getBytes(), "DES"));
		BDDMockito.when(dataEncryptionKeyRepository
				.findByConverterClassName(TestConverter.class.getName()))
				.thenReturn(Optional.of(dataEncryptionKey));

		Assertions.assertEquals("foo",
				dataEncryptionService.encryptString("foo", TestConverter.class));
		Assertions.assertEquals("foo",
				dataEncryptionService.decryptString("foo", TestConverter.class));

		Assertions.assertEquals(3, logWatcher.getMessages().size());
		Assertions.assertEquals("Cannot initialize cipher when trying to encrypt with converter "
				+ TestConverter.class.getName(), logWatcher.getMessages().get(0));
		Assertions.assertEquals("Cannot initialize cipher when trying to decrypt with converter "
				+ TestConverter.class.getName(), logWatcher.getMessages().get(1));
		Assertions.assertEquals("Cannot decrypt database column with converter "
				+ TestConverter.class.getName(), logWatcher.getMessages().get(2));
	}

	@Test
	public void testEncryptDecryptStringNullKey() {
		DataEncryptionService dataEncryptionService = new DataEncryptionService(
				EncryptionType.ENVIRONMENT, dataEncryptionKeyRepository);

		DataEncryptionKey dataEncryptionKey = new DataEncryptionKey();
		dataEncryptionKey.setConverterClassName(TestConverter.class.getName());
		dataEncryptionKey.setRotationInProgress(true);
		BDDMockito.when(dataEncryptionKeyRepository
				.findByConverterClassName(TestConverter.class.getName()))
				.thenReturn(Optional.of(dataEncryptionKey));

		Assertions.assertEquals("foo",
				dataEncryptionService.encryptString("foo", TestConverter.class));
		Assertions.assertEquals("foo",
				dataEncryptionService.decryptString("foo", TestConverter.class));

		Assertions.assertEquals(3, logWatcher.getMessages().size());
		Assertions.assertEquals("Skipping decryption with null key",
				logWatcher.getMessages().get(0));
		Assertions.assertEquals(
				"Retrying decryption with current key for converter " + TestConverter.class
						.getName(),
				logWatcher.getMessages().get(1));
		Assertions.assertEquals("Skipping decryption with null key",
				logWatcher.getMessages().get(2));
	}

	@Test
	public void testDecryptStringFailure() {
		DataEncryptionService dataEncryptionService = new DataEncryptionService(
				EncryptionType.ENVIRONMENT, dataEncryptionKeyRepository);

		DataEncryptionKey dataEncryptionKey = new DataEncryptionKey();
		dataEncryptionKey.setConverterClassName(TestConverter.class.getName());
		dataEncryptionKey.setCurrentKey(EncryptionUtils.generateKey());

		BDDMockito.when(dataEncryptionKeyRepository
				.findByConverterClassName(TestConverter.class.getName()))
				.thenReturn(Optional.of(dataEncryptionKey));

		String encrypted = dataEncryptionService.encryptString("foo", TestConverter.class);
		// Change current encryption key
		dataEncryptionKey.setCurrentKey(EncryptionUtils.generateKey());
		Assertions.assertEquals(encrypted,
				dataEncryptionService.decryptString(encrypted, TestConverter.class));

		Assertions.assertEquals(2, logWatcher.getMessages().size());
		Assertions.assertEquals("Cannot decrypt database column with converter "
				+ TestConverter.class.getName() + " with current key",
				logWatcher.getMessages().get(0));
		Assertions.assertEquals("Cannot decrypt database column with converter "
				+ TestConverter.class.getName(), logWatcher.getMessages().get(1));
	}

	@Test
	public void testDecryptStringPreviousKey() {
		DataEncryptionService dataEncryptionService = new DataEncryptionService(
				EncryptionType.ENVIRONMENT, dataEncryptionKeyRepository);

		Key key = EncryptionUtils.generateKey();

		DataEncryptionKey dataEncryptionKey = new DataEncryptionKey();
		dataEncryptionKey.setConverterClassName(TestConverter.class.getName());
		dataEncryptionKey.setCurrentKey(key);
		dataEncryptionKey.setPreviousKey(key);
		dataEncryptionKey.setRotationInProgress(true);

		BDDMockito.when(dataEncryptionKeyRepository
				.findByConverterClassName(TestConverter.class.getName()))
				.thenReturn(Optional.of(dataEncryptionKey));

		String encrypted = dataEncryptionService.encryptString("foo", TestConverter.class);
		Assertions.assertNotEquals("foo", encrypted);
		Assertions.assertEquals("foo",
				dataEncryptionService.decryptString(encrypted, TestConverter.class));

		Assertions.assertTrue(logWatcher.getMessages().isEmpty());
	}

	@Test
	public void testDecryptStringPreviousKeyInvalid() {
		logWatcher.withLevel(Level.ALL);
		DataEncryptionService dataEncryptionService = new DataEncryptionService(
				EncryptionType.ENVIRONMENT, dataEncryptionKeyRepository);

		Key key = EncryptionUtils.generateKey();

		DataEncryptionKey dataEncryptionKey = new DataEncryptionKey();
		dataEncryptionKey.setConverterClassName(TestConverter.class.getName());
		dataEncryptionKey.setCurrentKey(key);
		dataEncryptionKey.setPreviousKey(EncryptionUtils.generateKey());
		dataEncryptionKey.setRotationInProgress(true);

		BDDMockito.when(dataEncryptionKeyRepository
				.findByConverterClassName(TestConverter.class.getName()))
				.thenReturn(Optional.of(dataEncryptionKey));

		String encrypted = dataEncryptionService.encryptString("foo", TestConverter.class);
		Assertions.assertNotEquals("foo", encrypted);
		Assertions.assertEquals("foo",
				dataEncryptionService.decryptString(encrypted, TestConverter.class));

		Assertions.assertEquals(2, logWatcher.getMessages().size());
		Assertions.assertEquals("Cannot decrypt database column with converter "
				+ TestConverter.class.getName() + " with previous key",
				logWatcher.getMessages().get(0));
		Assertions.assertEquals(
				"Retrying decryption with current key for converter " + TestConverter.class
						.getName(),
				logWatcher.getMessages().get(1));
	}

	@Test
	public void testDecryptStringAlreadyDecrypted() {
		DataEncryptionService dataEncryptionService = new DataEncryptionService(
				EncryptionType.ENVIRONMENT, dataEncryptionKeyRepository);

		DataEncryptionKey dataEncryptionKey = new DataEncryptionKey();
		dataEncryptionKey.setConverterClassName(TestConverter.class.getName());
		dataEncryptionKey.setPreviousKey(EncryptionUtils.generateKey());
		dataEncryptionKey.setDisabled(true);
		BDDMockito.when(dataEncryptionKeyRepository
				.findByConverterClassName(TestConverter.class.getName()))
				.thenReturn(Optional.of(dataEncryptionKey));

		Assertions.assertEquals("foo",
				dataEncryptionService.decryptString("foo", TestConverter.class));

		Assertions.assertEquals(1, logWatcher.getMessages().size());
		Assertions.assertEquals("Skipping decryption with null key",
				logWatcher.getMessages().get(0));
	}

	static class TestConverter {

	}
}
