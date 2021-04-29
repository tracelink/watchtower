package com.tracelink.appsec.watchtower.core.scan.scm;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ApiTypeTest {

	@Test
	public void testAll() {
		ApiType type = ApiType.BITBUCKET_CLOUD;
		Assertions.assertEquals(type, ApiType.typeForName(type.getTypeName()));
	}

	@Test
	public void testNull() {
		Assertions.assertNull(ApiType.typeForName(""));
	}

}
