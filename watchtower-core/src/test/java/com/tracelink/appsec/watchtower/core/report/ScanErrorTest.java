package com.tracelink.appsec.watchtower.core.report;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ScanErrorTest {

	@Test
	public void testDAO() {
		String message = "TestMessage";
		ScanError error = new ScanError(message);
		Assertions.assertEquals(message, error.getErrorMessage());
	}

}
