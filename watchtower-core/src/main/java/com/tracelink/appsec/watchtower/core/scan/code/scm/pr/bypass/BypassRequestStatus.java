package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;

/**
 * Where a bypass request stands. Only {@link #PENDING} can change.
 *
 * @author Watchtower
 */
public enum BypassRequestStatus {
	/** Waiting for someone with the bypass privilege. */
	PENDING,
	/** Approved: the pull request was bypassed. */
	APPROVED,
	/** Declined by an approver. */
	DECLINED,
	/** Withdrawn by the requester. */
	WITHDRAWN,
	/** A newer scan of the pull request replaced the scan it was made on. */
	SUPERSEDED
}
