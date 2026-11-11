package com.tracelink.appsec.watchtower.core.scan;

import com.tracelink.appsec.watchtower.core.benchmark.Benchmarker;
import com.tracelink.appsec.watchtower.core.benchmark.WatchtowerBenchmarking;
import com.tracelink.appsec.watchtower.core.benchmark.WatchtowerTimers;
import com.tracelink.appsec.watchtower.core.exception.ScanInitializationException;
import com.tracelink.appsec.watchtower.core.module.scanner.IScanner;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles orchestration of individual scanners for scans of an SCM pull request. This class is
 * executed by one of the {@link AbstractScanningService}s.
 * <p>
 * Ensures that all objects are initialized and executes scanners against a working directory.
 * Collects reports and sends to the report method for implementations to manage. Finally, reports
 * on benchmarks, if configured and then starts a cleanup procedure for implementations
 *
 * @param <T> The type of {@link AbstractScanAgent} (for builder subclassing)
 * @param <S> The type of {@link IScanner} used to scan in this agent
 * @param <C> The type of {@link AbstractScanConfig} used to configure the scans
 * @param <R> The type of {@link AbstractScanReport} use to report findings from this scan
 * @author csmith, mcool
 */
public abstract class AbstractScanAgent<T extends AbstractScanAgent<T, S, C, R>, S extends IScanner<C, R>, C extends AbstractScanConfig, R extends AbstractScanReport>
		implements Runnable {

	private Logger LOG = LoggerFactory.getLogger(getClass());

	private String scanName;
	private Collection<S> scanners;
	private RulesetDto ruleset;
	private WatchtowerBenchmarking benchmarking;
	private volatile boolean failed = false;
	private MeterRegistry meterRegistry;
	private final List<ScanExecutionSummary.ScannerExecution> scannerExecutions =
			new ArrayList<>();

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

	/**
	 * Set the {@linkplain MeterRegistry} used to record {@code watchtower.scan.duration}
	 * (IMPROVEMENT_PLAN.md item 6.6). Optional: when not set, {@link #run()} skips
	 * timing rather than throwing, so existing callers/tests that never set this are
	 * unaffected. Subclasses that record their own metrics (e.g.
	 * {@code PRScanAgent}'s source-size summary) read it back via
	 * {@link #getMeterRegistry()} instead of keeping a second field.
	 *
	 * @param meterRegistry the registry to record metrics into
	 * @return this agent
	 */
	public T withMeterRegistry(MeterRegistry meterRegistry) {
		this.meterRegistry = meterRegistry;
		return (T) this;
	}

	/**
	 * @return the {@linkplain MeterRegistry} set via {@link #withMeterRegistry}, or null
	 *         if none was set
	 */
	protected MeterRegistry getMeterRegistry() {
		return this.meterRegistry;
	}

	/**
	 * The value for {@code watchtower.scan.duration}'s {@code type} tag
	 * (IMPROVEMENT_PLAN.md item 6.6). Defaults to {@code "unknown"} rather than being
	 * abstract, so a test double extending this class directly (as
	 * {@code AbstractScanAgentTest.MockScanAgent} does) does not need updating just to
	 * compile.
	 *
	 * @return a short label identifying this agent's scan type, e.g. {@code "pr"} or
	 *         {@code "upload"}
	 */
	protected String getMetricType() {
		return "unknown";
	}

	public String getScanName() {
		return this.scanName;
	}

	protected RulesetDto getRuleset() {
		return this.ruleset;
	}

	/**
	 * Get the scanners configured for this Agent
	 *
	 * @return the collection of scanners this agent will run
	 */
	protected Collection<S> getScanners() {
		return this.scanners;
	}

	protected boolean isBenchmarkingEnabled() {
		return this.benchmarking.isEnabled();
	}

	@Override
	public void run() {
		Timer.Sample durationSample = meterRegistry != null ? Timer.start(meterRegistry) : null;
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
			// Set unconditionally, before handleScanException() runs: a subclass
			// override may fully handle the exception (e.g. PRScanAgent re-enqueueing
			// a rate-limited scan via SQS - IMPROVEMENT_PLAN.md item 4.7) without
			// throwing further, but the run still hit a problem the caller may need to
			// know about (see hasFailed()).
			failed = true;
			handleScanException(e);
		} finally {
			clean();
			// IMPROVEMENT_PLAN.md item 6.6: recorded after clean() so the measured
			// duration covers the whole run(), not just the part before cleanup. Tagged
			// with failed's final value, so a rate-limited scan PRScanAgent re-enqueues
			// (IMPROVEMENT_PLAN.md item 4.7) still records result=failure - consistent
			// with hasFailed()'s own documented semantics: a handled exception is still
			// not a clean success.
			if (durationSample != null) {
				durationSample.stop(meterRegistry.timer("watchtower.scan.duration",
						"type", getMetricType(), "result", failed ? "failure" : "success"));
			}
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
	 * Reports whether {@link #run()} caught an exception from {@code initialize()},
	 * {@code scan()}, or {@code report()}. Unlike a completed
	 * {@link java.util.concurrent.CompletableFuture} wrapping this agent's
	 * {@code run()} - which always completes normally, since {@code run()} itself
	 * never lets an exception escape - this is the actual signal a caller needs to
	 * know whether the scan succeeded.
	 * <p>
	 * True whenever an exception occurred, regardless of whether a subclass's
	 * {@link #handleScanException(Exception)} override handled it without escalating
	 * further (e.g. PRScanAgent successfully re-enqueueing a rate-limited scan via SQS
	 * for a fresh attempt later - IMPROVEMENT_PLAN.md item 4.7). That is deliberate:
	 * from a caller deciding whether it is safe to consider this run's side effects
	 * final (e.g. deleting the SQS message that triggered it), a handled exception is
	 * still not a clean success.
	 *
	 * @return true if this run encountered an exception, false for a clean run
	 */
	public boolean hasFailed() {
		return failed;
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

		scanners.forEach(IScanner::prepareExecution);

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
		scannerExecutions.clear();

		// Create scan config
		C config = createScanConfig();

		for (S scanner : scanners) {
			String executionName = java.util.Objects.toString(scanner.executionName(), scanner.getClass().getName());
   String scannerName = executionName.substring(executionName.lastIndexOf('.') + 1).replaceFirst("Scanner$", "");
			if (!scanner.isDisabled() && shouldRunScanner(scanner, config)) {
				String notApplicable = null;
				try {
					notApplicable = notApplicableReason(scanner, config);
				} catch (RuntimeException e) {
					LOG.warn("Could not check the file types of " + scannerName + "; running it", e);
				}
				if (notApplicable != null) {
					// Nothing here for this scanner to look at: a finished check, not a skipped one.
					scannerExecutions.add(new ScanExecutionSummary.ScannerExecution(scannerName,
							ScanExecutionSummary.NOT_APPLICABLE, 0, notApplicable));
					onScannerOutcome(scanner, config, ScanExecutionSummary.NOT_APPLICABLE);
					continue;
				}
				long startedNanos = System.nanoTime();
				R report;
				String outcome = "FAILED";
				String failure = null;
				try {
					report = executeScanner(scanner, config);
					if (report == null) throw new IllegalStateException("Scanner produced no report");
					outcome = scannerOutcome(report);
					if ("FAILED".equals(outcome)) failure = failureReason(scanner, report);
				} catch (RuntimeException e) {
					failure = "The scanner stopped with " + e.getClass().getSimpleName() + ".";
					throw e;
				} finally {
					long durationMs = java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(
							System.nanoTime() - startedNanos);
					scannerExecutions.add(new ScanExecutionSummary.ScannerExecution(
							scannerName, outcome, Math.max(0, durationMs), failure));
					onScannerOutcome(scanner, config, outcome);
				}
				onScannerReport(scanner, config, report);
				if (config.isBenchmarkEnabled()) {
					report.logRuleBenchmarking();
				}
				reports.add(report);
			} else {
				LOG.debug("Skipping scanner " + scanner.getClass().getSimpleName());
				scannerExecutions.add(new ScanExecutionSummary.ScannerExecution(scannerName,
						!scanner.isDisabled() ? "SKIPPED" : "DISABLED", 0,
      !scanner.isDisabled() ? "No compatible rules in the selected ruleset" : "Module disabled or policy changed"));
    onScannerOutcome(scanner, config, !scanner.isDisabled() ? "SKIPPED" : "DISABLED");
			}
		}
		return reports;
	}

	protected ScanExecutionSummary getExecutionSummary() {
		return new ScanExecutionSummary(ruleset == null ? null : ruleset.getNumRules(),
				scannerExecutions);
	}

	protected String scannerOutcome(R report) { return "RAN"; }

	/**
	 * Why a scanner that finished is recorded as failed, in words for people and without any text
	 * quoted from the scanned code, or null when it cannot be told.
	 */
	protected String failureReason(S scanner, R report) { return null; }

	/**
	 * Why a scanner that is on and has compatible rules has nothing to look at in this scan, or
	 * null when it should run. Must fail open: anything unknown returns null.
	 *
	 * @param scanner the scanner about to run
	 * @param config  the scan config for the scanning process
	 * @return a short reason for people, or null to run the scanner
	 */
	protected String notApplicableReason(S scanner, C config) { return null; }
	protected void onScannerOutcome(S scanner, C config, String outcome) { }

	/**
	 * Hook called with the report of a scanner that ran, after its outcome is recorded, for details
	 * of what it produced that the one-word outcome does not carry (such as rules that could not run).
	 */
	protected void onScannerReport(S scanner, C config, R report) { }

	/** Hook for scan types that need to observe individual scanner execution. */
	protected R executeScanner(S scanner, C config) {
		return scanner.scan(config);
	}

	/**
	 * Determines whether the given scanner should be run based on the provided scan config
	 *
	 * @param scanner the scanner to run (or not)
	 * @param config  the scan config for the scanning process
	 * @return tru if the scanner should be run, false otherwise
	 */
    protected boolean shouldRunScanner(S scanner, C config) {
        if (scanner.isDisabled()) return false;
        List<Class<? extends RuleDto>> supportedRuleClasses = scanner.getSupportedRuleClass();
        if (supportedRuleClasses == null || supportedRuleClasses.isEmpty()) {
            LOG.info("Scanner {} has no supported rule class", scanner.getClass().getSimpleName());
            return false;
        }
        
        boolean shouldRun = config.getRuleset().getAllRules().stream()
                .anyMatch(r -> {
                    boolean isCompatible = isCompatible(supportedRuleClasses, r);
                    if (isCompatible) {
                        LOG.debug("Rule {} (class: {}) is compatible with scanner {}",
                                  r.getName(), 
                                  r.getClass().getName(), 
                                  scanner.getClass().getSimpleName());
                    } else {
                        LOG.debug("Rule {} (class: {}) is NOT compatible with scanner {}",
                                  r.getName(), 
                                  r.getClass().getName(), 
                                  scanner.getClass().getSimpleName());
                    }
                    return isCompatible;
                });
        
        LOG.info("Scanner {} will {} run",
                  scanner.getClass().getSimpleName(), 
                  shouldRun ? "" : " NOT");
        
        return shouldRun;
    }

	/**
	 * Whether the configured ruleset has at least one rule the given scanner can run - the same
	 * test as {@link #shouldRunScanner}, without its logging, for decisions made before the scan
	 * starts (e.g. which files to fetch).
	 *
	 * @param scanner the scanner to check
	 * @return true if the scanner will run against this agent's ruleset
	 */
	protected boolean rulesetHasRulesFor(S scanner) {
		List<Class<? extends RuleDto>> supportedRuleClasses = scanner.getSupportedRuleClass();
		if (ruleset == null || supportedRuleClasses == null || supportedRuleClasses.isEmpty()) {
			return false;
		}
		return ruleset.getAllRules().stream().anyMatch(r -> isCompatible(supportedRuleClasses, r));
	}

	private static boolean isCompatible(List<Class<? extends RuleDto>> supportedRuleClasses,
			RuleDto rule) {
		return supportedRuleClasses.stream()
				.anyMatch(supportedClass -> supportedClass.isAssignableFrom(rule.getClass()));
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
