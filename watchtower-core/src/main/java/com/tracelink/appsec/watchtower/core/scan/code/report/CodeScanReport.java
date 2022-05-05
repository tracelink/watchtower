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
	private List<CodeScanViolation> violations;

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
	}
}
