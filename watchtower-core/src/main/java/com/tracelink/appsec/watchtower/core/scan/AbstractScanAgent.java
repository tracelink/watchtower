package com.tracelink.appsec.watchtower.core.scan;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tracelink.appsec.watchtower.core.benchmark.Benchmarker;
import com.tracelink.appsec.watchtower.core.benchmark.WatchtowerBenchmarking;
import com.tracelink.appsec.watchtower.core.benchmark.WatchtowerTimers;
import com.tracelink.appsec.watchtower.core.exception.ScanInitializationException;
import com.tracelink.appsec.watchtower.core.module.scanner.IScanner;
import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

/**
 * Handles orchestration of individual scanners for scans of an SCM pull request. This class is
 * executed by one of the {@link AbstractScanningService}s.
 * <p>
 * Ensures that all objects are initialized and executes scanners against a working directory.
 * Collects reports and sends to the report method for implementations to manage. Finally, reports
 * on benchmarks, if configured and then starts a cleanup procedure for implementations
 *
 * @author csmith, mcool
 * @param <T> The type of {@link AbstractScanAgent} (for builder subclassing)
 */
public abstract class AbstractScanAgent<T extends AbstractScanAgent<T>>
		implements Runnable {
	private Logger LOG = LoggerFactory.getLogger(getClass());

	private String scanName;
	private Collection<IScanner> scanners;
	private RulesetDto ruleset;
	private WatchtowerBenchmarking benchmarking;
	private int threads;

	public AbstractScanAgent(String scanName) {
		this.scanName = scanName;
		benchmarking = new WatchtowerBenchmarking(scanName);
	}

	/**
	 * Set the scanners for this Agent's configuration
	 * 
	 * @param scanners the collection of scanners to use
	 * @return this agent
	 */
	public T withScanners(Collection<IScanner> scanners) {
		this.scanners = scanners;
		return (T) this;
	}

	/**
	 * Set the ruleset for this Agent's configuration
	 * 
	 * @param ruleset the ruleset to use
	 * @return this agent
	 */
	public T withRuleset(RulesetDto ruleset) {
		this.ruleset = ruleset;
		return (T) this;
	}

	/**
	 * Set whether this Agent should use benchmarking
	 * 
	 * @param benchmarkEnabled true to enable, false to disable benchmarks
	 * @return this agent
	 */
	public T withBenchmarkEnabled(boolean benchmarkEnabled) {
		benchmarking.enable(benchmarkEnabled);
		return (T) this;
	}

	/**
	 * Set the number of sub-threads this Agent can use
	 * <p>
	 * 0 means this is a single-threaded agent
	 * <p>
	 * 1 means this agent may use 1 additional thread, etc
	 * 
	 * @param threads the number of additional threads to use
	 * @return this agent
	 */
	public T withThreads(int threads) {
		this.threads = threads;
		return (T) this;
	}

	public String getScanName() {
		return this.scanName;
	}

	protected RulesetDto getRuleset() {
		return this.ruleset;
	}

	@Override
	public void run() {
		try {
			LOG.info("Starting Scan for scan: " + scanName);

			try (Benchmarker b =
					benchmarking.newBenchmarker(WatchtowerTimers.SCAN_TEST_SETUP)) {
				initialize();
			}
			List<ScanReport> reports;
			try (Benchmarker b =
					benchmarking.newBenchmarker(WatchtowerTimers.SCAN_ALL_SCANNERS)) {
				reports = scan();
			}
			try (Benchmarker b =
					benchmarking.newBenchmarker(WatchtowerTimers.SEND_REPORT)) {
				report(reports);
			}
			LOG.info("Report complete for scan: " + getScanName());

			// Log benchmark information
			if (benchmarking.isEnabled()) {
				benchmarking.report("\n");
			}

		} catch (Exception e) {
			handleScanException(e);
		} finally {
			clean();
		}
	}

	/**
	 * (Optional) Step to handle any exceptions encountered while processing. Defaults to doing
	 * nothing.
	 * 
	 * @param e the exception thrown
	 */
	protected void handleScanException(Exception e) {
		// intentionally blank
	}

	/**
	 * Does initialization routines and checks to ensure parameters are correct
	 * 
	 * @throws ScanInitializationException if the scan cannot begin
	 */
	protected void initialize() throws ScanInitializationException {
		if (getWorkingDirectory() == null) {
			throw new ScanInitializationException(
					"Error creating working directory for scan: " + scanName);
		}

		if (scanners == null) {
			throw new ScanInitializationException(
					"Scanner(s) must be configured.");
		}

		if (ruleset == null) {
			throw new ScanInitializationException("Ruleset must be configured");
		}

		if (threads < 0) {
			throw new ScanInitializationException(
					"Threads must be 0 or greater");
		}
	}

	/**
	 * Performs individual scans of whatever is in the working directory, using the scanners
	 * configured for this agent.
	 * 
	 * @return list of reports from the scanner(s)
	 */
	protected List<ScanReport> scan() {
		List<ScanReport> reports = new ArrayList<ScanReport>();

		// Create scan config
		ScanConfig config = new ScanConfig();
		config.setRuleset(ruleset);
		config.setWorkingDirectory(getWorkingDirectory());
		config.setThreads(threads);
		config.setBenchmarkEnabled(benchmarking.isEnabled());

		for (IScanner scanner : scanners) {
			if (config.getRuleset().getAllRules().stream().noneMatch(
					r -> scanner.getSupportedRuleClass() != null
							&& scanner.getSupportedRuleClass().isInstance(r))) {
				LOG.debug("No rules for scanner " + scanner.getClass().getSimpleName());
			} else {
				// Scan and format report
				ScanReport report = scanner.scan(config);
				if (config.isBenchmarkEnabled()) {
					report.logRuleBenchmarking();
				}
				reports.add(report);
			}
		}
		return reports;
	}

	/**
	 * Create a working directory
	 * 
	 * @return a Path to a working directory that this agent and scanners may use or null if an
	 *         exception occurred
	 */
	protected Path createWorkingDirectory() {
		Path workingDirectory = null;
		try {
			workingDirectory =
					Files.createTempDirectory(getScanName()).toFile().getCanonicalFile()
							.getAbsoluteFile().toPath();
			Files.createDirectories(workingDirectory);
		} catch (IOException e) {
			LOG.error("Could not create working directory", e);
		}
		return workingDirectory;
	}

	/**
	 * Do any necessary reporting given the raw reports from the scanners
	 * 
	 * @param reports a list of reports given by the scanners
	 */
	protected abstract void report(List<ScanReport> reports);

	/**
	 * Get the directory that this scan agent should scan against
	 * 
	 * @return a Path to a directory containing all data that should be scanned, or null if any
	 *         problem occurred
	 */
	protected abstract Path getWorkingDirectory();

	/**
	 * Do any cleanup necessary to close this scan agent. This always runs.
	 */
	protected abstract void clean();
}
