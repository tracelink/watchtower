package com.tracelink.appsec.watchtower.core.scan.scm;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ApiTypeTest {

	@Test
	public void testAll() {
		ScmApiType type = ScmApiType.BITBUCKET_CLOUD;
		Assertions.assertEquals(type, ScmApiType.typeForName(type.getTypeName()));
	}

	@Test
	public void testNull() {
		Assertions.assertNull(ScmApiType.typeForName(""));
	}

}
