package com.tracelink.appsec.watchtower.core.threadpool;

import java.util.concurrent.Callable;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.core.task.TaskRejectedException;

import com.tracelink.appsec.watchtower.core.scan.code.threadpool.PauseableThreadPoolTaskExecutor;

public class PauseableThreadPoolTaskExecutorTest {

	@Test
	public void testThreadPoolPause() {
		PauseableThreadPoolTaskExecutor ptp = new PauseableThreadPoolTaskExecutor(1);
		ptp.initialize();
		ptp.pause();
		Assertions.assertTrue(ptp.isPaused());
		ptp.resume();
		Assertions.assertFalse(ptp.isPaused());
	}

	@Test
	public void testThreadPoolPauseRunnable() throws Exception {
		PauseableThreadPoolTaskExecutor ptp = new PauseableThreadPoolTaskExecutor(1);
		ptp.initialize();
		final AtomicBoolean hasRun = new AtomicBoolean(false);
		Runnable runner = new Runnable() {
			@Override
			public void run() {
				hasRun.set(true);
			}
		};

		ptp.execute(runner);
		Thread.sleep(1000);
		Assertions.assertTrue(hasRun.get());

		hasRun.set(false);
		ptp.pause();

		ptp.execute(runner, 100L);
		Thread.sleep(1000);
		Assertions.assertFalse(hasRun.get());

		ptp.resume();
		Thread.sleep(1000);
		Assertions.assertTrue(hasRun.get());
	}

	@Test
	public void testThreadPoolPauseSubmit() throws Exception {
		PauseableThreadPoolTaskExecutor ptp = new PauseableThreadPoolTaskExecutor(1);
		ptp.initialize();

		final String returner = "Returned String";
		final AtomicBoolean hasRun = new AtomicBoolean(false);
		Callable<String> caller = new Callable<String>() {
			@Override
			public String call() throws Exception {
				hasRun.set(true);
				return returner;
			}

		};

		ptp.pause();
		Future<String> submitted = ptp.submit(caller);
		Assertions.assertFalse(hasRun.get());
		ptp.resume();
		Assertions.assertEquals(returner, submitted.get());
		Assertions.assertTrue(hasRun.get());
	}

	@Test
	public void testThreadPoolRunSubmit() throws Exception {
		PauseableThreadPoolTaskExecutor ptp = new PauseableThreadPoolTaskExecutor(1);
		ptp.initialize();

		final AtomicBoolean hasRun = new AtomicBoolean(false);
		Runnable runSubmit = new Runnable() {
			@Override
			public void run() {
				hasRun.set(true);
			}

		};

		ptp.submit(runSubmit).get();
		Assertions.assertTrue(hasRun.get());
	}

	@Test
	public void testThreadPoolRunSubmitListen() throws Exception {
		PauseableThreadPoolTaskExecutor ptp = new PauseableThreadPoolTaskExecutor(1);
		ptp.initialize();

		final AtomicBoolean hasRun = new AtomicBoolean(false);
		Runnable runSubmit = new Runnable() {
			@Override
			public void run() {
				hasRun.set(true);
			}

		};

		ptp.submitListenable(runSubmit).get();
		Assertions.assertTrue(hasRun.get());
	}

	@Test
	public void testThreadPoolCallSubmitListen() throws Exception {
		PauseableThreadPoolTaskExecutor ptp = new PauseableThreadPoolTaskExecutor(1);
		ptp.initialize();

		final AtomicBoolean hasRun = new AtomicBoolean(false);
		Callable<String> caller = new Callable<String>() {
			@Override
			public String call() throws Exception {
				hasRun.set(true);
				return "";
			}

		};

		ptp.submitListenable(caller).get();
		Assertions.assertTrue(hasRun.get());
	}

	@Test
	public void testRejectedExecutions() {
		PauseableThreadPoolTaskExecutor ptp = new PauseableThreadPoolTaskExecutor(1);
		ptp.initialize();

		Runnable runner = new Runnable() {
			@Override
			public void run() {
			}
		};
		Callable<String> caller = new Callable<String>() {
			@Override
			public String call() throws Exception {
				return null;
			}
		};

		ptp.shutdown();

		try {
			ptp.submit(runner);
		} catch (TaskRejectedException ex) {
			// correct
		} catch (Exception e) {
			Assertions.fail("Should not encounter another exception: " + e.getMessage());
		}

		try {
			ptp.submit(caller);
		} catch (TaskRejectedException ex) {
			// correct
		} catch (Exception e) {
			Assertions.fail("Should not encounter another exception: " + e.getMessage());
		}

		try {
			ptp.submitListenable(runner);
		} catch (TaskRejectedException ex) {
			// correct
		} catch (Exception e) {
			Assertions.fail("Should not encounter another exception: " + e.getMessage());
		}

		try {
			ptp.submitListenable(caller);
		} catch (TaskRejectedException ex) {
			// correct
		} catch (Exception e) {
			Assertions.fail("Should not encounter another exception: " + e.getMessage());
		}
	}

}
