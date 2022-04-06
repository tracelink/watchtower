package com.tracelink.appsec.watchtower.core.report;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanViolation;

public class ScanViolationTest {
	private CodeScanViolation vio1;
	private CodeScanViolation vio2;

	@BeforeEach
	public void setup() {
		vio1 = new CodeScanViolation();
		vio1.setViolationName("vio1");
		vio2 = new CodeScanViolation();
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

		CodeScanViolation sv = new CodeScanViolation();
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
