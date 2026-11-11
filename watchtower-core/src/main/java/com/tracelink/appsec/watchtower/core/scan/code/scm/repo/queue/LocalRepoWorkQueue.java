package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.queue;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import jakarta.annotation.PreDestroy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;

/**
 * Runs repository scan work in this process when no SQS queue is configured: one thread for
 * scans (so they run one at a time, in order) and one for jobs. For local and development use
 * on a single pod; queued work lives only in memory and in the rows, and is re-sent after a
 * restart by {@link RepoQueueStartup}.
 *
 * @author Watchtower
 */
public class LocalRepoWorkQueue implements RepoWorkQueue {

	private static final Logger LOG = LoggerFactory.getLogger(LocalRepoWorkQueue.class);

	static final long WAIT_FOR_PR_MILLIS = 5_000;

	private final ObjectProvider<RepoWorkProcessor> processor;

	private final ScheduledExecutorService scanExecutor = executor("repo-scan-local");

	private final ScheduledExecutorService jobExecutor = executor("repo-job-local");

	/**
	 * @param processor looked up when work runs, not when this is built: the processor in turn
	 *                  needs the services that send work here
	 */
	public LocalRepoWorkQueue(ObjectProvider<RepoWorkProcessor> processor) {
		this.processor = processor;
	}

	@Override
	public boolean sendScan(long scanId) {
		RepoQueueMessage message = RepoQueueMessage.scan(scanId);
		scanExecutor.execute(() -> run(message, scanExecutor));
		return true;
	}

	@Override
	public boolean sendJob(long jobId, String group) {
		RepoQueueMessage message = RepoQueueMessage.job(jobId);
		jobExecutor.execute(() -> run(message, jobExecutor));
		return true;
	}

	@Override
	public boolean isDistributed() {
		return false;
	}

	void run(RepoQueueMessage message, ScheduledExecutorService executor) {
		RepoWorkProcessor worker = processor.getObject();
		try {
			// Wait in place rather than requeue, so later scans cannot overtake this one
			while (message.kind() == RepoQueueMessage.Kind.SCAN ? !worker.canStartScan()
					: worker.isPaused()) {
				Thread.sleep(WAIT_FOR_PR_MILLIS);
			}
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			return;
		}
		WorkOutcome outcome = worker.process(message, () -> {
		});
		if (outcome.retry() && !executor.isShutdown()) {
			LOG.info("Retrying {} in {}s", message, outcome.delaySeconds());
			executor.schedule(() -> run(message, executor), outcome.delaySeconds(),
					TimeUnit.SECONDS);
		}
	}

	@PreDestroy
	void shutdown() {
		scanExecutor.shutdownNow();
		jobExecutor.shutdownNow();
	}

	private static ScheduledExecutorService executor(String name) {
		return Executors.newSingleThreadScheduledExecutor(runnable -> {
			Thread thread = new Thread(runnable, name);
			thread.setDaemon(true);
			return thread;
		});
	}
}
