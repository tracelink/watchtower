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

		ptp.submitCompletable(runSubmit).get();
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

		ptp.submitCompletable(caller).get();
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
			ptp.submitCompletable(runner);
		} catch (TaskRejectedException ex) {
			// correct
		} catch (Exception e) {
			Assertions.fail("Should not encounter another exception: " + e.getMessage());
		}

		try {
			ptp.submitCompletable(caller);
		} catch (TaskRejectedException ex) {
			// correct
		} catch (Exception e) {
			Assertions.fail("Should not encounter another exception: " + e.getMessage());
		}
	}

	@Test
	public void testQueueIsBoundedAndRejectsWhenFull() {
		// One thread, capacity one: the first task occupies the worker, the second fills
		// the queue, the third has nowhere to go. Before this the queue was unbounded, so
		// a webhook flood could queue agents until the heap ran out.
		PauseableThreadPoolTaskExecutor ptp = new PauseableThreadPoolTaskExecutor(1, 1);
		ptp.initialize();
		Assertions.assertEquals(1, ptp.getQueueCapacity());
		ptp.pause();
		try {
			Runnable noop = () -> {
			};
			ptp.execute(noop);
			ptp.execute(noop);
			Assertions.assertThrows(TaskRejectedException.class, () -> ptp.execute(noop));
		} finally {
			ptp.resume();
			ptp.shutdown();
		}
	}

	@Test
	public void testDefaultQueueCapacityIsApplied() {
		PauseableThreadPoolTaskExecutor ptp = new PauseableThreadPoolTaskExecutor(1);
		ptp.initialize();
		try {
			Assertions.assertEquals(PauseableThreadPoolTaskExecutor.DEFAULT_QUEUE_CAPACITY,
					ptp.getQueueCapacity());
		} finally {
			ptp.shutdown();
		}
	}

	@Test
	public void testNonPositiveQueueCapacityIsRejected() {
		Assertions.assertThrows(IllegalStateException.class,
				() -> new PauseableThreadPoolTaskExecutor(1, 0));
	}
}
