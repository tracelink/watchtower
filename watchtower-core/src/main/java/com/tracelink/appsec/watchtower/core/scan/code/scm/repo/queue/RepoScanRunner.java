package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.queue;

/**
 * Runs one queued repository scan to completion.
 *
 * @author Watchtower
 */
public interface RepoScanRunner {

	/**
	 * Claims the scan for this pod and runs it, recording the result on its row. Must not
	 * throw: every failure is recorded on the row and reported through the outcome.
	 *
	 * @param scanId the {@code repo_scans} row to run
	 * @return what to do with the scan's queue message
	 */
	WorkOutcome run(long scanId);
}
