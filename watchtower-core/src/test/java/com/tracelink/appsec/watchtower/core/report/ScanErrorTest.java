package com.tracelink.appsec.watchtower.core.report;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanError;

public class ScanErrorTest {

	@Test
	public void testDAO() {
		String message = "TestMessage";
		CodeScanError error = new CodeScanError(message);
		Assertions.assertEquals(message, error.getErrorMessage());
	}

}
