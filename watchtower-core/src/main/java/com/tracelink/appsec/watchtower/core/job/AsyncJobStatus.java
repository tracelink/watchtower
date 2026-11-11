package com.tracelink.appsec.watchtower.core.job;

/**
 * Where an {@link AsyncJobEntity} is in its life.
 *
 * @author Watchtower
 */
public enum AsyncJobStatus {
	QUEUED, RUNNING, DONE, FAILED;

	public boolean isFinished() {
		return this == DONE || this == FAILED;
	}
}
