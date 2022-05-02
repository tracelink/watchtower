package com.tracelink.appsec.watchtower.core.scan;

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
 * @param <S> The type of {@link IScanner} used to scan in this agent
 * @param <C> The type of {@link AbstractScanConfig} used to configure the scans
 * @param <R> The type of {@link AbstractScanReport} use to report findings from this scan
 */
public abstract class AbstractScanAgent<T extends AbstractScanAgent<T, S, C, R>, S extends IScanner<C, R>, C extends AbstractScanConfig, R extends AbstractScanReport>
		implements Runnable {
	private Logger LOG = LoggerFactory.getLogger(getClass());

	private String scanName;
	private Collection<S> scanners;
	private RulesetDto ruleset;
	private WatchtowerBenchmarking benchmarking;

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
	public T withScanners(Collection<S> scanners) {
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

	public String getScanName() {
		return this.scanName;
	}

	protected RulesetDto getRuleset() {
		return this.ruleset;
	}

	protected boolean isBenchmarkingEnabled() {
		return this.benchmarking.isEnabled();
	}

	@Override
	public void run() {
		try {
			LOG.info("Starting Scan for scan: " + scanName);

			try (Benchmarker b =
					benchmarking.newBenchmarker(WatchtowerTimers.SCAN_TEST_SETUP)) {
				initialize();
			}
			List<R> reports;
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
		LOG.error("Exception while scanning. Scan Name: " + getScanName(), e);
	}

	/**
	 * Does initialization routines and checks to ensure parameters are correct
	 * 
	 * @throws ScanInitializationException if the scan cannot begin
	 */
	protected void initialize() throws ScanInitializationException {
		if (scanners == null) {
			throw new ScanInitializationException(
					"Scanner(s) must be configured.");
		}

		if (ruleset == null) {
			throw new ScanInitializationException("Ruleset must be configured");
		}

	}

	/**
	 * Performs individual scans of whatever is in the working directory, using the scanners
	 * configured for this agent.
	 * 
	 * @return list of reports from the scanner(s)
	 */
	protected List<R> scan() {
		List<R> reports = new ArrayList<>();

		// Create scan config
		C config = createScanConfig();

		for (S scanner : scanners) {
			if (config.getRuleset().getAllRules().stream().noneMatch(
					r -> scanner.getSupportedRuleClass() != null
							&& scanner.getSupportedRuleClass().isInstance(r))) {
				LOG.debug("No rules for scanner " + scanner.getClass().getSimpleName());
			} else {
				// Scan and format report
				R report = scanner.scan(config);
				if (config.isBenchmarkEnabled()) {
					report.logRuleBenchmarking();
				}
				reports.add(report);
			}
		}
		return reports;
	}

	/**
	 * Create the Scan Configuration for this scan
	 * 
	 * @return the Scan Configuration
	 */
	protected abstract C createScanConfig();

	/**
	 * Do any necessary reporting given the raw reports from the scanners
	 * 
	 * @param reports a list of reports given by the scanners
	 */
	protected abstract void report(List<R> reports);

	/**
	 * Do any cleanup necessary to close this scan agent. This always runs.
	 */
	protected abstract void clean();
}
