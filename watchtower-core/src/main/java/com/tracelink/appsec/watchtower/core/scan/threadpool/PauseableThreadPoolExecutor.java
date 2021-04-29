package com.tracelink.appsec.watchtower.core.scan.threadpool;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class PauseableThreadPoolExecutor extends ThreadPoolExecutor {

	private static Logger LOG = LoggerFactory.getLogger(PauseableThreadPoolExecutor.class);

	PauseableThreadPoolExecutor(int corePoolSize, int maximumPoolSize,
			BlockingQueue<Runnable> workQueue) {
		super(corePoolSize, maximumPoolSize, 10L, TimeUnit.SECONDS, workQueue);
	}

	private volatile boolean isPaused;

	private final ReentrantLock pauseLock = new ReentrantLock();

	private final Condition unpaused = pauseLock.newCondition();
	private int additionalTasksPaused = 0;

	@Override
	protected void beforeExecute(Thread t, Runnable r) {
		super.beforeExecute(t, r);
		additionalTasksPaused++;
		pauseLock.lock();
		try {
			while (isPaused) {
				unpaused.await();
			}
		} catch (InterruptedException ie) {
			t.interrupt();
		} finally {
			pauseLock.unlock();
		}
		additionalTasksPaused--;
	}

	void pause() {
		pauseLock.lock();
		try {
			isPaused = true;
			LOG.warn("ThreadPool has been PAUSED");
		} finally {
			pauseLock.unlock();
		}

	}

	boolean isPaused() {
		return this.isPaused;
	}

	void resume() {
		pauseLock.lock();
		try {
			isPaused = false;
			unpaused.signalAll();
			LOG.warn("ThreadPool has been RESUMED");
		} finally {
			pauseLock.unlock();
		}
	}

	@Override
	public long getTaskCount() {
		return super.getTaskCount() + additionalTasksPaused;
	}
}
