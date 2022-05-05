package com.tracelink.appsec.watchtower.core.scan.code.report;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/**
 * DAO of a scan violation
 *
 * @author csmith
 */
public class CodeScanViolation {
	private String violationName;
	private int lineNum;
	private RulePriority severity;
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

	public RulePriority getSeverity() {
		return severity;
	}

	public void setSeverity(RulePriority severity) {
		this.severity = severity;
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
