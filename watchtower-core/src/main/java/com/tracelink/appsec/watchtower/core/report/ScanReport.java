package com.tracelink.appsec.watchtower.core.report;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tracelink.appsec.watchtower.core.benchmark.Benchmarking;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;

/**
 * The report for any scan. Contains methods to get list of violations, a list of errors, and the
 * count of files scanned.
 *
 * @author csmith, mcool
 */
public class ScanReport {
	private static final Logger LOG = LoggerFactory.getLogger(ScanReport.class);

	private List<ScanError> errors;
	private List<ScanViolation> violations;

	private Benchmarking<? extends RuleDto> ruleBenchmarking;

	public ScanReport() {
		errors = new ArrayList<ScanError>();
		violations = new ArrayList<ScanViolation>();
	}

	/**
	 * add an error to this report
	 * 
	 * @param error an error for this report
	 */
	public void addError(ScanError error) {
		errors.add(error);
	}

	/**
	 * add a violation to this report
	 * 
	 * @param violation a violation for this report
	 */
	public void addViolation(ScanViolation violation) {
		violations.add(violation);
	}

	public List<ScanError> getErrors() {
		return Collections.unmodifiableList(errors);
	}

	public List<ScanViolation> getViolations() {
		return Collections.unmodifiableList(violations);
	}

	public void setRuleBenchmarking(Benchmarking<? extends RuleDto> ruleBenchmarking) {
		this.ruleBenchmarking = ruleBenchmarking;
	}

	/**
	 * log any benchmarking results if there are any. Only called if config is set for benchmarking
	 */
	public void logRuleBenchmarking() {
		if (ruleBenchmarking != null) {
			LOG.info(ruleBenchmarking.report("\n"));
		}
	}

	/**
	 * Joins the data from the provided {@linkplain ScanReport} into this one
	 * 
	 * @param other the other scan report
	 */
	public void join(ScanReport other) {
		errors.addAll(other.getErrors());
		violations.addAll(other.getViolations());
	}
}
