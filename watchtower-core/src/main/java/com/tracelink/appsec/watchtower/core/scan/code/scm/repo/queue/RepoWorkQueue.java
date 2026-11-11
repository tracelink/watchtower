package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.queue;

/**
 * Where repository scan work is sent. With an SQS queue configured the work is shared by every
 * pod and scans run one at a time across the cluster; without one, the work runs in this
 * process (local and development use, one pod only).
 *
 * @author Watchtower
 */
public interface RepoWorkQueue {

	/**
	 * Queues a scan. Scans run one at a time, in the order they are sent.
	 *
	 * @param scanId the {@code repo_scans} row to run
	 * @return true if the scan was queued
	 */
	boolean sendScan(long scanId);

	/**
	 * Queues a background job. Jobs in different groups run independently of each other and of
	 * scans; jobs in one group run one at a time.
	 *
	 * @param jobId the {@code async_jobs} row to run
	 * @param group the job's group
	 * @return true if the job was queued
	 */
	boolean sendJob(long jobId, String group);

	/**
	 * @return true if work is shared through SQS, so any pod may run it
	 */
	boolean isDistributed();
}
