package com.tracelink.appsec.watchtower.core.scan.code.report;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleExecutionIdentity;

/**
 * DAO of a scan violation
 *
 * @author csmith
 */
public class CodeScanViolation {
	private ProviderFindingDetails providerDetails;
	public ProviderFindingDetails getProviderDetails() { return providerDetails; }
	public void setProviderDetails(ProviderFindingDetails details) { providerDetails = details; }
	private String violationName;
	private int lineNum;
	private RulePriority severity;
	private String fileName;
	private String message;
	private RuleExecutionIdentity ruleIdentity;
	private Boolean effectiveBlocking;
	private String engineFingerprint;

	public Boolean getEffectiveBlocking() { return effectiveBlocking; }
	public void setEffectiveBlocking(Boolean blocking) { effectiveBlocking = blocking; }
	public String getEngineFingerprint() { return engineFingerprint; }
	public void setEngineFingerprint(String fingerprint) { engineFingerprint = fingerprint; }

	/** Null on legacy reports; supplied by the scanner from its selected definition. */
	public RuleExecutionIdentity getRuleIdentity() { return ruleIdentity; }

	public void setRuleIdentity(RuleExecutionIdentity ruleIdentity) {
		this.ruleIdentity = ruleIdentity;
	}

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
