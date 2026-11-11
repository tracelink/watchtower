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

	private String externalUrl;

	private com.tracelink.appsec.watchtower.core.rule.RuleChange ruleChange;

	/** The saved violation's id; not part of equality, which compares what was found. */
	private long violationId;

	/** The scanner module and rule that produced it, when recorded; not part of equality. */
	private String scannerModule;
	private Long ruleId;

	public String getScannerModule() { return scannerModule; }
	public void setScannerModule(String scannerModule) { this.scannerModule = scannerModule; }
	public Long getRuleId() { return ruleId; }
	public void setRuleId(Long ruleId) { this.ruleId = ruleId; }

	public long getViolationId() {
		return violationId;
	}

	public void setViolationId(long violationId) {
		this.violationId = violationId;
	}

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

	public String getExternalUrl() {
		return externalUrl;
	}

	public void setExternalUrl(String externalUrl) {
		this.externalUrl = externalUrl;
	}

	/** @return what happened to the rule after this scan, or null when nothing is known to have */
	public com.tracelink.appsec.watchtower.core.rule.RuleChange getRuleChange() {
		return ruleChange;
	}

	public void setRuleChange(com.tracelink.appsec.watchtower.core.rule.RuleChange ruleChange) {
		this.ruleChange = ruleChange;
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
					this.message.equals(temp.message) &&
					Objects.equals(this.externalUrl, temp.externalUrl);
		}
		return false;
	}

	@Override
	public int hashCode() {
		return Objects.hash(violationName, lineNumber, severity, severityValue, fileName, message,
				externalUrl);
	}

}
