package com.tracelink.appsec.watchtower.core.scan.code.report;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanReport;

/**
 * The report for any scan. Contains methods to get list of violations, a list of errors, and the
 * count of files scanned.
 *
 * @author csmith, mcool
 */
public class CodeScanReport extends AbstractScanReport {
	private List<CodeScanError> errors;
 private String executionStatus;
 public String getExecutionStatus(){return executionStatus;}
 public void setExecutionStatus(String status){this.executionStatus=status;}
	private List<CodeScanViolation> violations;
	// Rules the scanner could not run (for example a rule that is configured wrongly), by name, with why. The scanner
	// itself still ran, so these mark only those rules as not run, not the whole scanner.
	private final java.util.Map<String, String> failedRules = new java.util.LinkedHashMap<>();

	public CodeScanReport() {
		errors = new ArrayList<CodeScanError>();
		violations = new ArrayList<CodeScanViolation>();
	}

	/**
	 * add an error to this report
	 * 
	 * @param error an error for this report
	 */
	public void addError(CodeScanError error) {
		errors.add(error);
	}

	/**
	 * add a violation to this report
	 * 
	 * @param violation a violation for this report
	 */
	public void addViolation(CodeScanViolation violation) {
		violations.add(violation);
	}

	/**
	 * Records that one rule could not run in this scan although its scanner did.
	 *
	 * @param ruleName the rule's name as the ruleset knows it
	 * @param reason why it could not run
	 */
	public void addFailedRule(String ruleName, String reason) {
		if (ruleName != null && !ruleName.isBlank()) {
			failedRules.putIfAbsent(ruleName, reason);
		}
	}

	/**
	 * @return the rules that could not run, by name with the reason
	 */
	public java.util.Map<String, String> getFailedRules() {
		return Collections.unmodifiableMap(failedRules);
	}

	public List<CodeScanError> getErrors() {
		return Collections.unmodifiableList(errors);
	}

	public List<CodeScanViolation> getViolations() {
		return Collections.unmodifiableList(violations);
	}

	/**
	 * Joins the data from the provided {@linkplain CodeScanReport} into this one
	 * 
	 * @param other the other scan report
	 */
	public void join(CodeScanReport other) {
		errors.addAll(other.getErrors());
		violations.addAll(other.getViolations());
		other.getFailedRules().forEach(this::addFailedRule);
	}
}
