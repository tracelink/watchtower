package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result;

import java.util.Objects;

/**
 * Helper class to hold important information about the results of a PR violation
 * 
 * @author csmith
 *
 */
public class PRScanResultViolation {
	private String violationName;

	private int lineNumber;

	private String severity;

	private int severityValue;

	private String fileName;

	private String message;

	public String getViolationName() {
		return violationName;
	}

	public void setViolationName(String violationName) {
		this.violationName = violationName;
	}

	public int getLineNumber() {
		return lineNumber;
	}

	public void setLineNumber(int lineNumber) {
		this.lineNumber = lineNumber;
	}

	public String getSeverity() {
		return severity;
	}

	public void setSeverity(String severity) {
		this.severity = severity;
	}

	public int getSeverityValue() {
		return severityValue;
	}

	public void setSeverityValue(int severityValue) {
		this.severityValue = severityValue;
	}

	public String getFileName() {
		return fileName;
	}

	public void setFileName(String fileName) {
		this.fileName = fileName;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof PRScanResultViolation) {
			PRScanResultViolation temp = (PRScanResultViolation) obj;
			return this.violationName.equals(temp.violationName) &&
					this.lineNumber == temp.lineNumber &&
					this.severity.equals(temp.severity) &&
					this.severityValue == temp.severityValue &&
					this.fileName.equals(temp.fileName) &&
					this.message.equals(temp.message);
		}
		return false;
	}

	@Override
	public int hashCode() {
		return Objects.hash(violationName, lineNumber, severity, severityValue, fileName, message);
	}

}
