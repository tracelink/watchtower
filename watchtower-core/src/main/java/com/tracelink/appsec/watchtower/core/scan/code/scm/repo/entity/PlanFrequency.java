package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity;

/**
 * How often a repository scan plan runs. {@code ONCE} is an ad-hoc scan: it runs when submitted
 * and never again.
 *
 * @author Watchtower
 */
public enum PlanFrequency {
	ONCE("Once"), DAILY("Daily"), WEEKLY("Weekly"), MONTHLY("Monthly");

	private final String displayName;

	PlanFrequency(String displayName) {
		this.displayName = displayName;
	}

	public String getDisplayName() {
		return displayName;
	}

	public boolean isRecurring() {
		return this != ONCE;
	}
}
