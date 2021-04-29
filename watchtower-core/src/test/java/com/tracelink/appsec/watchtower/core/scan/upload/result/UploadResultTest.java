package com.tracelink.appsec.watchtower.core.scan.upload.result;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;


public class UploadResultTest {

	@Test
	public void testDAO() {
		String name = "name";
		String submittedBy = "submitBy";
		String status = "foo";
		String error = "err";
		String ticket = "123";
		String ruleset = "ruleset";
		LocalDateTime submitDate = LocalDateTime.now().minus(1L, ChronoUnit.HOURS);
		LocalDateTime endDate = LocalDateTime.now();

		String violationName = "violation";
		int lineNumber = 1;
		String severity = "High";
		int severityValue = 5;
		String fileName = "filename";
		String message = "message";

		UploadScanResultViolation violation = new UploadScanResultViolation();
		violation.setViolationName(violationName);
		violation.setLineNumber(lineNumber);
		violation.setSeverity(severity);
		violation.setSeverityValue(severityValue);
		violation.setFileName(fileName);
		violation.setMessage(message);

		UploadScanResult result = new UploadScanResult();
		result.setName(name);
		result.setSubmittedBy(submittedBy);
		result.setStatus(status);
		result.setErrorMessage(error);
		result.setTicket(ticket);
		result.setRuleset(ruleset);
		result.setSubmitDate(submitDate);
		result.setEndDate(endDate);

		result.setViolations(Arrays.asList(violation));

		Assertions.assertEquals(name, result.getName());
		Assertions.assertEquals(submittedBy, result.getSubmittedBy());
		Assertions.assertEquals(status, result.getStatus());
		Assertions.assertEquals(error, result.getErrorMessage());
		Assertions.assertEquals(ticket, result.getTicket());
		Assertions.assertEquals(ruleset, result.getRuleset());
		Assertions.assertEquals(submitDate, result.getSubmitDate());
		Assertions.assertEquals(endDate, result.getEndDate());
		Assertions.assertEquals(1, result.getViolationsFound());

		UploadScanResultViolation retVio = result.getViolations().get(0);
		Assertions.assertEquals(violationName, retVio.getViolationName());
		Assertions.assertEquals(lineNumber, retVio.getLineNumber());
		Assertions.assertEquals(severity, retVio.getSeverity());
		Assertions.assertEquals(severityValue, retVio.getSeverityValue());
		Assertions.assertEquals(fileName, retVio.getFileName());
		Assertions.assertEquals(message, retVio.getMessage());
	}
}
