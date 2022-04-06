package com.tracelink.appsec.watchtower.core.scan.image.report;

/**
 * DAO of a scan violation
 *
 * @author csmith
 */
public class ImageScanViolation {
	private String violationName;
	private int lineNum;
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

	public int getLineNum() {
		return lineNum;
	}

	public void setLineNum(int lineNum) {
		this.lineNum = lineNum;
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

}
