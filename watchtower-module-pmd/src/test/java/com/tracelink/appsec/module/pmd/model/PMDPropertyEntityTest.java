package com.tracelink.appsec.module.pmd.model;

import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class PMDPropertyEntityTest {

	@Test
	public void testToDto() {
		PMDPropertyEntity property = new PMDPropertyEntity();
		property.setName("xpath");
		property.setValue("foo");
		PMDPropertyDto dto = property.toDto();
		Assertions.assertEquals(Optional.of(0L), Optional.of(dto.getId()));
		Assertions.assertEquals("xpath", dto.getName());
		Assertions.assertEquals("foo", dto.getValue());
	}
}
