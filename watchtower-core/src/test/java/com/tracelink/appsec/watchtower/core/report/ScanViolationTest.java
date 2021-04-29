package com.tracelink.appsec.watchtower.core.report;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class ScanViolationTest {
	private ScanViolation vio1;
	private ScanViolation vio2;

	@BeforeEach
	public void setup() {
		vio1 = new ScanViolation();
		vio1.setViolationName("vio1");
		vio2 = new ScanViolation();
		vio2.setViolationName("vio2");
	}

	@Test
	public void testDAO() {
		String vioName = "TestViolation";
		String fileName = "TestFileName";
		int lineNum = 111;
		String message = "TestMessage";
		String severity = "TestSeverity";
		int severityValue = 123;

		ScanViolation sv = new ScanViolation();
		sv.setViolationName(vioName);
		Assertions.assertEquals(vioName, sv.getViolationName());

		sv.setFileName(fileName);
		Assertions.assertEquals(fileName, sv.getFileName());

		sv.setLineNum(lineNum);
		Assertions.assertEquals(lineNum, sv.getLineNum());

		sv.setMessage(message);
		Assertions.assertEquals(message, sv.getMessage());

		sv.setSeverity(severity);
		Assertions.assertEquals(severity, sv.getSeverity());

		sv.setSeverityValue(severityValue);
		Assertions.assertEquals(severityValue, sv.getSeverityValue());
	}

}
