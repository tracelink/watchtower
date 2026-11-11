package com.tracelink.appsec.watchtower.core.metrics;

/** Read-only 30-day values displayed in the home KPI row. */
public final class HomeOverviewModel {
	private final long completed;
	private final long failedIncomplete;
	private final long findings;
	private final String averageDuration;

	public HomeOverviewModel(long completed, long failedIncomplete, long findings,
			String averageDuration) {
		this.completed = completed;
		this.failedIncomplete = failedIncomplete;
		this.findings = findings;
		this.averageDuration = averageDuration;
	}

	public long getCompleted() { return completed; }
	public long getFailedIncomplete() { return failedIncomplete; }
	public long getFindings() { return findings; }
	public String getAverageDuration() { return averageDuration; }
}
