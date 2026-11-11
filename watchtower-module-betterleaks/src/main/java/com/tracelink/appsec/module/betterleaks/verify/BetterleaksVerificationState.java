package com.tracelink.appsec.module.betterleaks.verify;

import com.tracelink.appsec.watchtower.core.verification.LiveVerificationStatus;

/**
 * Where a verification is: queued, being checked, or done with a result.
 *
 * @author Watchtower
 */
public enum BetterleaksVerificationState {
	PENDING, RUNNING, LIVE, INVALID, UNVERIFIABLE, ERROR;

	/**
	 * @return true while the check is still to come
	 */
	public boolean isActive() {
		return this == PENDING || this == RUNNING;
	}

	/**
	 * @return the status users see; queued and running both show as pending
	 */
	public LiveVerificationStatus toStatus() {
		return isActive() ? LiveVerificationStatus.PENDING : LiveVerificationStatus.valueOf(name());
	}

	/**
	 * @param status a finished check's result
	 * @return the matching state
	 */
	public static BetterleaksVerificationState of(LiveVerificationStatus status) {
		return status == LiveVerificationStatus.PENDING ? PENDING : valueOf(status.name());
	}
}
