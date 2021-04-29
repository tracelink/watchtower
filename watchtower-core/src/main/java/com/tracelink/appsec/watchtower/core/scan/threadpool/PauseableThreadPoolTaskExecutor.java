package com.tracelink.appsec.watchtower.core.scan.threadpool;

import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;

import org.springframework.core.task.AsyncListenableTaskExecutor;
import org.springframework.core.task.TaskRejectedException;
import org.springframework.scheduling.SchedulingTaskExecutor;
import org.springframework.scheduling.concurrent.ExecutorConfigurationSupport;
import org.springframework.util.Assert;
import org.springframework.util.concurrent.ListenableFuture;
import org.springframework.util.concurrent.ListenableFutureTask;

/**
 * Handles logic around pausing or resuming tasks on an executor queue
 *
 * @author csmith
 */
public class PauseableThreadPoolTaskExecutor extends ExecutorConfigurationSupport
		implements AsyncListenableTaskExecutor, SchedulingTaskExecutor {

	private static final long serialVersionUID = -2456802575609852046L;

	private static final int SHUTDOWN_TIMEOUT = 60;

	private PauseableThreadPoolExecutor threadPool;

	private final int threads;

	public PauseableThreadPoolTaskExecutor(int numThreads) {
		super();
		setWaitForTasksToCompleteOnShutdown(true);
		setAwaitTerminationSeconds(SHUTDOWN_TIMEOUT);
		this.threads = numThreads;
	}

	@Override
	protected ExecutorService initializeExecutor(ThreadFactory threadFactory,
			RejectedExecutionHandler rejectedExecutionHandler) {
		threadPool = new PauseableThreadPoolExecutor(threads, threads,
				new LinkedBlockingQueue<Runnable>());
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

	@Override
	public ListenableFuture<?> submitListenable(Runnable task) {
		ExecutorService executor = getThreadPoolExecutor();
		try {
			ListenableFutureTask<Object> future = new ListenableFutureTask<Object>(task, null);
			executor.execute(future);
			return future;
		} catch (RejectedExecutionException ex) {
			throw new TaskRejectedException(
					"Executor [" + executor + "] did not accept task: " + task, ex);
		}
	}

	@Override
	public <T> ListenableFuture<T> submitListenable(Callable<T> task) {
		ExecutorService executor = getThreadPoolExecutor();
		try {
			ListenableFutureTask<T> future = new ListenableFutureTask<T>(task);
			executor.execute(future);
			return future;
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
