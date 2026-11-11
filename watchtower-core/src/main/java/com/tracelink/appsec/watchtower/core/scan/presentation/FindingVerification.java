package com.tracelink.appsec.watchtower.core.scan.presentation;

import com.tracelink.appsec.watchtower.core.verification.LiveVerificationStatus;

/**
 * The "Verify live" state of one report finding.
 *
 * @param violationId the pull request violation to verify
 * @param status      the latest result, or null if never requested
 * @param canRequest  whether the viewing user may request a verification
 * @author Watchtower
 */
public record FindingVerification(long violationId, LiveVerificationStatus status,
		boolean canRequest) {

	/**
	 * @return the status shown on the finding; empty if never requested
	 */
	public String statusLabel() {
		return status == null ? "" : status.getLabel();
	}

	/**
	 * @return the status as a stable key for styling; empty if never requested
	 */
	public String statusKey() {
		return status == null ? "" : status.name();
	}

	/**
	 * @return what the status means; empty if never requested
	 */
	public String statusDescription() {
		return status == null ? "" : status.getDescription();
	}
}
