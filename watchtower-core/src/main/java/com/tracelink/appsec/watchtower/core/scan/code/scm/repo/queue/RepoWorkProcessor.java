package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.queue;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import jakarta.annotation.PreDestroy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.tracelink.appsec.watchtower.core.job.AsyncJobService;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanningService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.RepoScanSettingsService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;

/**
 * Runs one queued unit of repository scan work, whichever queue delivered it. While the work
 * runs, a heartbeat keeps both its row (so no other pod takes it over) and its queue lease
 * alive. Pull request scans come first: repository work is only taken while this pod's pull
 * request pool is idle.
 *
 * @author Watchtower
 */
@Component
public class RepoWorkProcessor {

	private static final Logger LOG = LoggerFactory.getLogger(RepoWorkProcessor.class);

	private final RepoScanRunner scanRunner;

	private final AsyncJobService jobService;

	private final RepoScanRepository scans;

	private final RepoScanSettingsService settings;

	private final PRScanningService prScanning;

	private final WorkerIdentity worker;

	private final long heartbeatSeconds;

	private final ScheduledExecutorService heartbeats =
			Executors.newSingleThreadScheduledExecutor(runnable -> {
				Thread thread = new Thread(runnable, "repo-scan-heartbeat");
				thread.setDaemon(true);
				return thread;
			});

	@Autowired
	public RepoWorkProcessor(RepoScanRunner scanRunner, AsyncJobService jobService,
			RepoScanRepository scans, RepoScanSettingsService settings,
			PRScanningService prScanning, WorkerIdentity worker,
			@Value("${watchtower.reposcan.heartbeat-seconds:60}") long heartbeatSeconds) {
		this.scanRunner = scanRunner;
		this.jobService = jobService;
		this.scans = scans;
		this.settings = settings;
		this.prScanning = prScanning;
		this.worker = worker;
		this.heartbeatSeconds = heartbeatSeconds;
	}

	/**
	 * @return true if repository scan work is paused on every pod
	 */
	public boolean isPaused() {
		return settings.isPaused();
	}

	/**
	 * @return true if this pod should start a repository scan now: scans are not paused and no
	 *         pull request scan is running or waiting here
	 */
	public boolean canStartScan() {
		return !isPaused() && prScanning.getTaskNumActive() == 0
				&& prScanning.getTaskNumInQueue() == 0;
	}

	/**
	 * @param message     the work to run
	 * @param extendLease keeps the queue's hold on the message, run with every heartbeat
	 * @return what to do with the message
	 */
	public WorkOutcome process(RepoQueueMessage message, Runnable extendLease) {
		ScheduledFuture<?> heartbeat = heartbeats.scheduleAtFixedRate(
				() -> beat(message, extendLease), heartbeatSeconds, heartbeatSeconds,
				TimeUnit.SECONDS);
		try {
			return message.kind() == RepoQueueMessage.Kind.SCAN ? scanRunner.run(message.id())
					: jobService.run(message.id());
		} catch (RuntimeException e) {
			// Runners record their own failures; anything reaching here is a bug. Drop the
			// message rather than redeliver it forever.
			LOG.error("Unexpected failure running " + message, e);
			return WorkOutcome.done();
		} finally {
			heartbeat.cancel(false);
		}
	}

	void beat(RepoQueueMessage message, Runnable extendLease) {
		try {
			extendLease.run();
			if (message.kind() == RepoQueueMessage.Kind.SCAN) {
				scans.heartbeat(message.id(), worker.id(), System.currentTimeMillis(),
						ScanStatus.IN_PROGRESS);
			} else {
				jobService.progress(message.id(), null);
			}
		} catch (RuntimeException e) {
			LOG.warn("Heartbeat failed for " + message, e);
		}
	}

	@PreDestroy
	void shutdown() {
		heartbeats.shutdownNow();
	}
}
