package com.tracelink.appsec.watchtower.core.scan.image.report;

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
public class ImageScanReport extends AbstractScanReport {
	private List<ImageScanError> errors;
	private List<ImageScanViolation> violations;
	private boolean scanTimedOut;

	public ImageScanReport() {
		errors = new ArrayList<ImageScanError>();
		violations = new ArrayList<ImageScanViolation>();
		scanTimedOut = false;
	}

	/**
	 * add an error to this report
	 * 
	 * @param error an error for this report
	 */
	public void addError(ImageScanError error) {
		errors.add(error);
	}

	/**
	 * add a violation to this report
	 * 
	 * @param violation a violation for this report
	 */
	public void addViolation(ImageScanViolation violation) {
		violations.add(violation);
	}

	public List<ImageScanError> getErrors() {
		return Collections.unmodifiableList(errors);
	}

	public List<ImageScanViolation> getViolations() {
		return Collections.unmodifiableList(violations);
	}
	public boolean getScanTimedOut() {
		return scanTimedOut;
	}
	public void setScanTimedOut(boolean timedOut) {
		scanTimedOut = timedOut;
	}

}
