package com.tracelink.appsec.watchtower.core.encryption.converter;

import java.security.Key;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.encryption.service.KeyEncryptionService;
import com.tracelink.appsec.watchtower.core.encryption.utils.EncryptionUtils;

@ExtendWith(SpringExtension.class)
public class DataEncryptionKeyConverterTest {

	@MockBean
	private KeyEncryptionService keyEncryptionService;

	@Test
	public void testConvertToDatabaseColumn() {
		DataEncryptionKeyConverter converter = new DataEncryptionKeyConverter(
				keyEncryptionService);

		Key key = EncryptionUtils.generateKey();
		BDDMockito.when(keyEncryptionService.encryptKey(key)).thenReturn("bar");

		Assertions.assertEquals("bar", converter.convertToDatabaseColumn(key));
	}

	@Test
	public void testConvertToEntityAttribute() {
		DataEncryptionKeyConverter converter = new DataEncryptionKeyConverter(
				keyEncryptionService);

		Key key = EncryptionUtils.generateKey();
		BDDMockito.when(keyEncryptionService.decryptKey("bar")).thenReturn(key);

		Assertions.assertEquals(key, converter.convertToEntityAttribute("bar"));
	}
}
