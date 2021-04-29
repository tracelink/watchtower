package com.tracelink.appsec.watchtower.core.encryption.converter;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.encryption.service.DataEncryptionService;

@ExtendWith(SpringExtension.class)
public class StringEncryptedAttributeConverterTest {

	@MockBean
	private DataEncryptionService dataEncryptionService;

	@Test
	public void testConvertEntityAttributeToString() {
		StringEncryptedAttributeConverter converter = new StringEncryptedAttributeConverter(
				dataEncryptionService);
		Assertions.assertEquals("foo", converter.convertEntityAttributeToString("foo"));
	}

	@Test
	public void testConvertStringToEntityAttribute() {
		StringEncryptedAttributeConverter converter = new StringEncryptedAttributeConverter(
				dataEncryptionService);
		Assertions.assertEquals("foo", converter.convertStringToEntityAttribute("foo"));
	}

	@Test
	public void testConvertToDatabaseColumn() {
		StringEncryptedAttributeConverter converter = new StringEncryptedAttributeConverter(
				dataEncryptionService);

		BDDMockito.when(dataEncryptionService.encryptString("foo", converter.getClass()))
				.thenReturn("bar");

		Assertions.assertEquals("bar", converter.convertToDatabaseColumn("foo"));
	}

	@Test
	public void testConvertToEntityAttribute() {
		StringEncryptedAttributeConverter converter = new StringEncryptedAttributeConverter(
				dataEncryptionService);

		BDDMockito.when(dataEncryptionService.decryptString("bar", converter.getClass()))
				.thenReturn("foo");

		Assertions.assertEquals("foo", converter.convertToEntityAttribute("bar"));
	}
}
