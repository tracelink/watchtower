package com.tracelink.appsec.watchtower.core.scan;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tracelink.appsec.watchtower.core.benchmark.Benchmarker;
import com.tracelink.appsec.watchtower.core.benchmark.WatchtowerBenchmarking;
import com.tracelink.appsec.watchtower.core.benchmark.WatchtowerTimers;
import com.tracelink.appsec.watchtower.core.exception.ScanInitializationException;
import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

/**
 * Handles orchestration of individual scanners for scans. This class is executed by one of the
 * {@link AbstractScanningService}s.
 * <p>
 * Ensures that all objects are initialized and executes scanners. Collects reports and sends to the
 * report method for implementations to manage. Finally, reports on benchmarks, if configured and
 * then starts a cleanup procedure for implementations
 *
 * @author csmith, mcool
 * @param <T> The type of {@link AbstractScanAgent} (for builder subclassing)
 */
public abstract class AbstractScanAgent<T extends AbstractScanAgent<T>>
		implements Runnable {
	private Logger LOG = LoggerFactory.getLogger(getClass());

	private String scanName;

	private RulesetDto ruleset;
	private WatchtowerBenchmarking benchmarking;

	public AbstractScanAgent(String scanName) {
		this.scanName = scanName;
		benchmarking = new WatchtowerBenchmarking(scanName);
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

	protected String getScanName() {
		return this.scanName;
	}

	protected RulesetDto getRuleset() {
		return this.ruleset;
	}

	protected WatchtowerBenchmarking getBenchmarking() {
		return benchmarking;
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

	protected abstract List<ScanReport> scan();

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
		if (ruleset == null) {
			throw new ScanInitializationException("Ruleset must be configured");
		}
	}

	/**
	 * Do any necessary reporting given the raw reports from the scanners
	 * 
	 * @param reports a list of reports given by the scanners
	 */
	protected abstract void report(List<ScanReport> reports);

	/**
	 * Do any cleanup necessary to close this scan agent. This always runs.
	 */
	protected abstract void clean();
}
