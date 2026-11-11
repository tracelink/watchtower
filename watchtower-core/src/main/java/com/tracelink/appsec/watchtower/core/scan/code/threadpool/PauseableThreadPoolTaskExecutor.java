package com.tracelink.appsec.watchtower.core.scan.code.threadpool;

import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.task.TaskRejectedException;
import org.springframework.scheduling.SchedulingTaskExecutor;
import org.springframework.scheduling.concurrent.ExecutorConfigurationSupport;
import org.springframework.util.Assert;

/**
 * Handles logic around pausing or resuming tasks on an executor queue
 *
 * @author csmith
 */
public class PauseableThreadPoolTaskExecutor extends ExecutorConfigurationSupport
		implements SchedulingTaskExecutor {

	private static final long serialVersionUID = -2456802575609852046L;

	private static final Logger LOG =
			LoggerFactory.getLogger(PauseableThreadPoolTaskExecutor.class);

	private static final int SHUTDOWN_TIMEOUT = 60;

	/**
	 * Scans allowed to wait in the queue before further submissions are rejected. The
	 * queue used to be unbounded, so a webhook flood could queue agents until the heap
	 * ran out. Rejecting is preferable: the caller learns immediately and Bitbucket can
	 * retry the delivery.
	 */
	public static final int DEFAULT_QUEUE_CAPACITY = 100;

	private PauseableThreadPoolExecutor threadPool;

	private final int threads;

	private final int queueCapacity;

	public PauseableThreadPoolTaskExecutor(int numThreads) {
		this(numThreads, DEFAULT_QUEUE_CAPACITY);
	}

	public PauseableThreadPoolTaskExecutor(int numThreads, int queueCapacity) {
		super();
		setWaitForTasksToCompleteOnShutdown(true);
		setAwaitTerminationSeconds(SHUTDOWN_TIMEOUT);
		Assert.state(numThreads > 0,
				"Number of threads for Task Executor must be a positive integer");
		Assert.state(queueCapacity > 0,
				"Queue capacity for Task Executor must be a positive integer");
		this.threads = numThreads;
		this.queueCapacity = queueCapacity;
	}

	public int getQueueCapacity() {
		return this.queueCapacity;
	}

	@Override
	protected ExecutorService initializeExecutor(ThreadFactory threadFactory,
			RejectedExecutionHandler rejectedExecutionHandler) {
		threadPool = new PauseableThreadPoolExecutor(threads, threads,
				new LinkedBlockingQueue<Runnable>(queueCapacity));
		// The default AbortPolicy already throws, which execute() turns into a
		// TaskRejectedException for the caller. This only adds the log line, so a
		// rejection is visible in the pod logs rather than only in an HTTP response.
		threadPool.setRejectedExecutionHandler((task, executor) -> {
			LOG.error("Scan queue is full (capacity " + queueCapacity
					+ ", active " + executor.getActiveCount()
					+ "). Rejecting submission; the caller should retry later.");
			new ThreadPoolExecutor.AbortPolicy().rejectedExecution(task, executor);
		});
		return threadPool;
	}

	@Override
	public void execute(Runnable task) {
		Executor executor = getThreadPoolExecutor();
		try {
			executor.execute(task);
		} catch (RejectedExecutionException ex) {
			throw new TaskRejectedException(
					"Executor [" + executor + "] did not accept task: " + task, ex);
		}

	}

	private ThreadPoolExecutor getThreadPoolExecutor() throws IllegalStateException {
		Assert.state(this.threadPool != null, "ThreadPoolTaskExecutor not initialized");
		return this.threadPool;
	}

	public long getTaskNumInQueue() {
		return getThreadPoolExecutor().getQueue().size();
	}

	public long getTaskNumActive() {
		return getThreadPoolExecutor().getActiveCount();
	}

	/**
	 * Unlock the queue to allow processing
	 */
	public void resume() {
		this.threadPool.resume();
	}

	/**
	 * Check the pause/resume status of the queue
	 *
	 * @return true if paused, false if running
	 */
	public boolean isPaused() {
		return this.threadPool.isPaused();
	}

	/**
	 * Lock the queue to prevent processing
	 */
	public void pause() {
		this.threadPool.pause();
	}

	@Override
	public void execute(Runnable task, long startTimeout) {
		execute(task);
	}

	@Override
	public Future<?> submit(Runnable task) {
		ExecutorService executor = getThreadPoolExecutor();
		try {
			return executor.submit(task);
		} catch (RejectedExecutionException ex) {
			throw new TaskRejectedException(
					"Executor [" + executor + "] did not accept task: " + task, ex);
		}
	}

	@Override
	public <T> Future<T> submit(Callable<T> task) {
		ExecutorService executor = getThreadPoolExecutor();
		try {
			return executor.submit(task);
		} catch (RejectedExecutionException ex) {
			throw new TaskRejectedException(
					"Executor [" + executor + "] did not accept task: " + task, ex);
		}
	}

	/**
	 * This task executor prefers short-lived work units.
	 */
	@Override
	public boolean prefersShortLivedTasks() {
		return true;
	}
}
