package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.mergegate;

import java.util.List;

/**
 * Merges in a window, by what Watchtower knew when each happened. Shown on the pull request
 * results page's Merge gate tab and returned by {@code /rest/scan/result/merge-gate}.
 *
 * @param days                       the window, in days
 * @param since                      its start, epoch millis
 * @param merges                     pull requests merged in it
 * @param scannedClean               merged after a clean scan of the merged commit
 * @param mergedBeforeScan           merged with no completed scan of the merged commit
 * @param mergedWithBlockingFindings merged after a scan of the merged commit blocked
 * @param topRepositories            the repositories with the most ungated merges, most first
 * @param pullRequests               every merge that was not scanned clean, newest first
 * @param truncated                  whether the window held more merges than are read, so the
 *                                   figures cover only the newest of them
 * @author Watchtower
 */
public record MergeGateReport(int days, long since, int merges, int scannedClean,
		BeforeScan mergedBeforeScan, Blocking mergedWithBlockingFindings,
		List<RepositoryCount> topRepositories, List<MergedPullRequestRow> pullRequests,
		boolean truncated) {

	/** Merges with no completed scan of the merged commit, by why. */
	public record BeforeScan(int total, int scanInProgress, int newerCommitNotScanned,
			int scanFailed, int neverScanned) {
	}

	/** Merges whose scan blocked, by whether a bypass covered the blocking findings. */
	public record Blocking(int total, int bypassed, int notBypassed) {
	}

	/**
	 * One repository's merges.
	 *
	 * @param ungated merged before a scan, or with blocking findings nothing bypassed
	 */
	public record RepositoryCount(String apiLabel, String repository, int merges,
			int mergedBeforeScan, int mergedWithUnbypassedBlockers, int ungated) {
	}

	/**
	 * One merge that was not scanned clean.
	 *
	 * @param link         the pull request in the SCM, or null if its integration is gone
	 * @param mergedAt     when the SCM says it was merged, epoch millis
	 * @param mergedCommit the commit merged, or null when the SCM did not say
	 * @param outcome      what Watchtower knew when it was merged
	 * @param reason       that, in words
	 */
	public record MergedPullRequestRow(String apiLabel, String repository, String prId,
			String link, long mergedAt, String mergedCommit, MergeGateOutcome outcome,
			String reason) {
	}
}
