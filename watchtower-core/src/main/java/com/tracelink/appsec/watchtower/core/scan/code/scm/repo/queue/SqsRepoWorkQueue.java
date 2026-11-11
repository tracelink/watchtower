package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.queue;

import com.tracelink.appsec.watchtower.core.queue.SqsQueueClient;

/**
 * Sends repository scan work to the SQS FIFO queue shared by every pod. Every scan is in one
 * message group, so SQS hands out the next scan only after the previous one's message is
 * deleted: one scan at a time across the cluster, with no locking in Watchtower.
 *
 * @author Watchtower
 */
public class SqsRepoWorkQueue implements RepoWorkQueue {

	static final String SCAN_GROUP = "scan";

	private final SqsQueueClient client;

	public SqsRepoWorkQueue(SqsQueueClient client) {
		this.client = client;
	}

	@Override
	public boolean sendScan(long scanId) {
		return client.send(RepoQueueMessage.scan(scanId).toJson(), SCAN_GROUP, "scan-" + scanId);
	}

	@Override
	public boolean sendJob(long jobId, String group) {
		return client.send(RepoQueueMessage.job(jobId).toJson(), group, "job-" + jobId);
	}

	@Override
	public boolean isDistributed() {
		return true;
	}
}
