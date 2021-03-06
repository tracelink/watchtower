package com.tracelink.appsec.watchtower.core.scan.code.scm;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiType;

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
