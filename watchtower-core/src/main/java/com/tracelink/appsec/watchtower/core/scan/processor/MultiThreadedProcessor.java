package com.tracelink.appsec.watchtower.core.scan.processor;

import java.nio.file.Path;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletionService;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

/**
 * Manages a multi-threaded execution of a processor scan. the processor will find files and for
 * each file add a task to do the actual scan, then collect the file report results eventually to
 * add to the final report
 *
 * @author csmith
 */
public class MultiThreadedProcessor extends AbstractProcessor {
	private final ExecutorService executor;
	private final CompletionService<ScanReport> completionService;

	private long submittedTasks = 0L;

	public MultiThreadedProcessor(CallableCreator processor, int threads) {
		super(processor);
		executor = Executors.newFixedThreadPool(threads, new ThreadFactory() {
			private final AtomicInteger counter = new AtomicInteger();

			@Override
			public Thread newThread(Runnable r) {
				return new Thread(r, "ProcessorThread " + counter.incrementAndGet());
			}
		});
		completionService = new ExecutorCompletionService<ScanReport>(executor);
	}

	@Override
	protected void processFile(Callable<ScanReport> callable) {
		completionService.submit(callable);
		submittedTasks++;
	}

	@Override
	public void runScan(final RulesetDto ruleset, Path startingPath) {
		super.runScan(ruleset, startingPath);

		for (long i = 0; i < submittedTasks; i++) {
			try {
				final ScanReport report = completionService.take().get();
				this.addReport(report);
			} catch (final InterruptedException ie) {
				Thread.currentThread().interrupt();
			} catch (final ExecutionException ee) {
				final Throwable t = ee.getCause();
				this.addSystemException(t);
			}
		}
		executor.shutdownNow();
	}

}
