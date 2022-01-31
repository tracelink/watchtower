package com.tracelink.appsec.watchtower.core.scan;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;

import com.tracelink.appsec.watchtower.core.scan.threadpool.PauseableThreadPoolTaskExecutor;

/**
 * Handles creating executor services and scheduling scans in a
 * {@linkplain PauseableThreadPoolTaskExecutor}.
 * 
 * @author csmith
 *
 */
public abstract class AbstractScanningService {
	private static Logger LOG = LoggerFactory.getLogger(AbstractScanningService.class);

	private PauseableThreadPoolTaskExecutor executor;
	private boolean isQuiesced = false;

	private final boolean runAfterStartup;

	protected AbstractScanningService(int executorThreads, boolean shouldRecoverFromDowntime) {
		this.executor = new PauseableThreadPoolTaskExecutor(executorThreads);
		this.executor.setBeanName(this.getClass().getSimpleName());
		this.executor.initialize();
		this.runAfterStartup = shouldRecoverFromDowntime;
	}

	public PauseableThreadPoolTaskExecutor getExecutor() {
		return executor;
	}

	/**
	 * Halts processing new scans using {@linkplain PauseableThreadPoolTaskExecutor#pause()}
	 */
	public void pauseExecution() {
		this.getExecutor().pause();
	}

	public boolean isPaused() {
		return this.getExecutor().isPaused();
	}

	/**
	 * Resumes processing scans using {@linkplain PauseableThreadPoolTaskExecutor#resume()}
	 */
	public void resumeExecution() {
		this.getExecutor().resume();
	}

	/**
	 * Sets a flag to reject new scans
	 */
	public void quiesce() {
		isQuiesced = true;
		LOG.warn(this.getClass().getSimpleName() + " entering QUIESCE state");
	}

	public boolean isQuiesced() {
		return isQuiesced;
	}

	/**
	 * Unsets a flag, allowing new scans
	 */
	public void unQuiesce() {
		isQuiesced = false;
	}

	/**
	 * Initiate a graceful shutdown of this orchestrator
	 */
	public void shutdown() {
		this.getExecutor().shutdown();
	}

	public long getTaskNumInQueue() {
		return this.getExecutor().getTaskNumInQueue();
	}

	public long getTaskNumActive() {
		return this.getExecutor().getTaskNumActive();
	}

	/**
	 * After Watchtower is fully live, attempt any processing needed to "catch up" on scans between
	 * when the server went down and now.
	 */
	@EventListener(ApplicationReadyEvent.class)
	public void afterStartup() {
		if (runAfterStartup) {
			recoverFromDowntime();
		} else {
			LOG.info("Skipping Downtime Recovery due to 'runAfterStartup' being false");
		}
	}

	protected abstract void recoverFromDowntime();
}
