package com.tracelink.appsec.watchtower.core.scan.code;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tracelink.appsec.watchtower.core.exception.ScanInitializationException;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanAgent;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanningService;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;

/**
 * Handles orchestration of individual scanners for scans of an SCM pull request. This class is
 * executed by one of the {@link AbstractScanningService}s.
 * <p>
 * Ensures that all objects are initialized and executes scanners against a working directory.
 * Collects reports and sends to the report method for implementations to manage. Finally, reports
 * on benchmarks, if configured and then starts a cleanup procedure for implementations
 *
 * @author csmith, mcool
 * @param <T> The type of {@link AbstractCodeScanAgent} (for builder subclassing)
 */
public abstract class AbstractCodeScanAgent<T extends AbstractCodeScanAgent<T>>
		extends
		AbstractScanAgent<T, ICodeScanner, CodeScanConfig, CodeScanReport> {
	private Logger LOG = LoggerFactory.getLogger(getClass());

	private static final int MAX_WORKING_DIRECTORY_PREFIX = 64;

	private int threads;
	private Path workingDirectory;
	private CodeScanExecutionSnapshot executionSnapshot;
	private com.tracelink.appsec.watchtower.core.rule.candidate.RuleShadowService candidateShadow;

	public T withCandidateShadow(com.tracelink.appsec.watchtower.core.rule.candidate.RuleShadowService shadow) {
		this.candidateShadow = shadow;
		return (T) this;
	}

	protected boolean shadowComparisonEnabled() { return candidateShadow != null && candidateShadow.enabled(); }

	protected void recordShadowComparison(String type, long id) {
		if (!shadowComparisonEnabled()) return;
		try { candidateShadow.compare(type, id, createScanConfig()); }
		catch (RuntimeException e) { LOG.warn("Candidate shadow comparison unavailable; normal scan result preserved"); }
	}

	@Override
	protected List<CodeScanReport> scan() {
		executionSnapshot = null;
		matchedFileTypes = null;
		List<CodeScanReport> reports = super.scan();
		// Also retain the selected ruleset for scans with no installed/compatible engines.
		if (executionSnapshot == null) captureExecutionSnapshot(createScanConfig());
		return reports;
	}

	private java.util.Set<Long> heldRules = java.util.Set.of();
	private java.util.Set<String> heldNames = java.util.Set.of();

	/** Immutable sets reject contains(null): findings without a managed rule are never held. */
	private boolean held(com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanViolation violation) {
		var identity = violation.getRuleIdentity();
		if (identity != null && identity.ruleId() != null) return heldRules.contains(identity.ruleId());
		// Some engines (e.g. PMD) report an unmanaged identity; fall back to the held rule's name.
		return violation.getViolationName() != null && heldNames.contains(violation.getViolationName());
	}

	private void captureExecutionSnapshot(CodeScanConfig config) {
		if (executionSnapshot == null) {
			executionSnapshot = CodeScanExecutionSnapshot.capture(config.getRuleset(), getScanners(), config);
			heldRules = config.getRuleset() == null ? java.util.Set.of() : config.getRuleset().getAllRules().stream()
					.filter(r -> r.getId() != null && r.getStewardship() != null && r.getStewardship().isUpstreamHeld())
					.map(r -> r.getId()).collect(java.util.stream.Collectors.toUnmodifiableSet());
			heldNames = config.getRuleset() == null ? java.util.Set.of() : config.getRuleset().getAllRules().stream()
					.filter(r -> r.getName() != null && r.getStewardship() != null && r.getStewardship().isUpstreamHeld())
					.map(r -> r.getName()).collect(java.util.stream.Collectors.toUnmodifiableSet());
		}
	}

	@Override
	protected CodeScanReport executeScanner(ICodeScanner scanner, CodeScanConfig config) {
		captureExecutionSnapshot(config);
		if (scanner.getExecutionCapability() == com.tracelink.appsec.watchtower.core.module.scanner.ExecutionCapability.REMOTE_SERVICE) {
			CodeScanReport remote = new CodeScanReport();
			remote.addError(new com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanError(
					"Remote assessment requires durable PR or repository dispatch"));
			return remote;
		}
		CodeScanReport report;
		config.setFileTypes(fileTypesOf(scanner));
		try {
			report = super.executeScanner(scanner, config);
		} finally {
			config.setFileTypes(null);
		}
		if (report != null) {
			String engineKey = executionSnapshot.engineKey(CodeScanExecutionSnapshot.scannerName(scanner));
			report.getViolations().forEach(violation -> {
				violation.setEngineFingerprint("unknown".equals(engineKey) ? null : engineKey);
				// R5.4: a provided rule held after an upstream upgrade reports but never blocks.
				violation.setEffectiveBlocking(violation.getSeverity() == null ? null
						: executionSnapshot.blockingLevel() != null
								&& violation.getSeverity().compareTo(executionSnapshot.blockingLevel()) <= 0
								&& !held(violation));
			});
		}
		return report;
	}

	/**
	 * A scanner's file types, or an empty list (every file) when it cannot say. Asking must never
	 * stop a scan: a scanner that cannot be asked simply runs on everything, as before.
	 */
	protected static List<String> fileTypesOf(ICodeScanner scanner) {
		try {
			List<String> types = scanner.getFileTypes();
			return types == null ? List.of() : types.stream().filter(java.util.Objects::nonNull).toList();
		} catch (RuntimeException e) {
			return List.of();
		}
	}

	/** Which of every scanner's file types occur in the working directory; looked up once per scan. */
	private java.util.Set<String> matchedFileTypes;

	@Override
	protected String notApplicableReason(ICodeScanner scanner, CodeScanConfig config) {
		List<String> types = fileTypesOf(scanner);
		if (types.isEmpty() || hasFileOfType(types, config)) {
			return null;
		}
		return "No " + ScannerFileTypes.describe(types) + " files in this scan";
	}

	/**
	 * Whether the scan holds a file of one of these types. Scans that know which files they are
	 * about (a pull request's changed files) override this; the default looks through the working
	 * directory, once for all scanners.
	 *
	 * @param types the scanner's file types, never empty
	 * @param config the scan config
	 * @return true if there is something for the scanner to look at, or if that cannot be told
	 */
	protected boolean hasFileOfType(List<String> types, CodeScanConfig config) {
		if (matchedFileTypes == null) {
			java.util.Set<String> all = new java.util.LinkedHashSet<>();
			for (ICodeScanner each : getScanners()) {
				all.addAll(fileTypesOf(each));
			}
			matchedFileTypes = ScannerFileTypes.matchedTypes(config.getWorkingDirectory(), all);
		}
		return types.stream().anyMatch(matchedFileTypes::contains);
	}

	@Override
	protected String failureReason(ICodeScanner scanner, CodeScanReport report) {
		return com.tracelink.appsec.watchtower.core.scan.code.report.ScannerFailureReason.summarize(
				report.getErrors().stream().map(com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanError::getErrorMessage).toList(),
				scanner.isSensitive());
	}

	@Override
	protected String scannerOutcome(CodeScanReport report) {
		return report.getExecutionStatus() != null ? report.getExecutionStatus() : report.getErrors().isEmpty() ? "RAN" : "FAILED";
	}

	@Override
	protected void onScannerOutcome(ICodeScanner scanner, CodeScanConfig config, String outcome) {
		captureExecutionSnapshot(config);
		executionSnapshot = executionSnapshot.withOutcome(scanner, outcome);
	}

	@Override
	protected void onScannerReport(ICodeScanner scanner, CodeScanConfig config, CodeScanReport report) {
		// The scanner ran; only the rules it could not run are recorded as not run.
		if (!report.getFailedRules().isEmpty()) {
			captureExecutionSnapshot(config);
			executionSnapshot = executionSnapshot.withFailedRules(scanner, report.getFailedRules().keySet());
		}
	}

	@Override
	protected ScanExecutionSummary getExecutionSummary() {
		var summary = super.getExecutionSummary();
		return new ScanExecutionSummary(
				executionSnapshot == null ? summary.rulesEvaluated() : executionSnapshot.rules().size(),
				summary.scanners(), executionSnapshot);
	}

	public AbstractCodeScanAgent(String scanName) {
		super(scanName);
		workingDirectory = createWorkingDirectory();
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

	/**
	 * Does initialization routines and checks to ensure parameters are correct
	 * 
	 * @throws ScanInitializationException if the scan cannot begin
	 */
	protected void initialize() throws ScanInitializationException {
		super.initialize();
		if (getWorkingDirectory() == null) {
			throw new ScanInitializationException(
					"Error creating working directory for scan: " + getScanName());
		}

		if (threads < 0) {
			throw new ScanInitializationException(
					"Threads must be 0 or greater");
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected CodeScanConfig createScanConfig() {
		// Create scan config
		CodeScanConfig config = new CodeScanConfig();
		config.setRuleset(getRuleset());
		config.setWorkingDirectory(getWorkingDirectory());
		config.setThreads(threads);
		config.setBenchmarkEnabled(isBenchmarkingEnabled());
		return config;
	}

	/**
	 * Create a working directory
	 * 
	 * @return a Path to a working directory that this agent and scanners may use or null if an
	 *         exception occurred
	 */
	/**
	 * The scan name comes from the SCM (repository and PR id) or a user, so only safe
	 * characters reach the file system: anything else becomes {@code _}. A path separator
	 * would otherwise make {@link Files#createTempDirectory} fail the scan.
	 *
	 * @param scanName the scan's name
	 * @return a temp-directory name prefix of letters, digits, {@code . _ -}, at most 64 long
	 */
	static String workingDirectoryPrefix(String scanName) {
		String safe = StringUtils.trimToEmpty(scanName).replaceAll("[^A-Za-z0-9._-]", "_");
		return safe.isEmpty() ? "scan" : StringUtils.left(safe, MAX_WORKING_DIRECTORY_PREFIX);
	}

	protected Path createWorkingDirectory() {
		Path workingDirectory = null;
		try {
			workingDirectory =
					Files.createTempDirectory(workingDirectoryPrefix(getScanName())).toFile()
							.getCanonicalFile().getAbsoluteFile().toPath();
			Files.createDirectories(workingDirectory);
		} catch (IOException e) {
			LOG.error("Could not create working directory", e);
		}
		return workingDirectory;
	}

	/**
	 * The folders a full repository download deletes: those that <em>every</em> scanner this
	 * ruleset runs excludes (see {@link ICodeScanner#getExcludedFolders()}). Only scanners with
	 * rules in the ruleset count - every registered scanner is handed to the agent, and one
	 * the ruleset never runs must not change what is downloaded. With no such scanner, the
	 * defaults apply, exactly as before scanners could declare their own.
	 *
	 * @return the folder names to delete after a full download, never null
	 */
	protected Set<String> determineExcludedFolders() {
		Collection<ICodeScanner> scanners = getScanners();
		if (scanners == null) {
			return ICodeScanner.DEFAULT_EXCLUDED_FOLDERS;
		}
		return scanners.stream()
				.filter(scanner -> !scanner.isDisabled()).filter(this::rulesetHasRulesFor)
				.map(scanner -> scanner.getExcludedFolders() == null
						? ICodeScanner.DEFAULT_EXCLUDED_FOLDERS
						: scanner.getExcludedFolders())
				.reduce((left, right) -> left.stream().filter(right::contains)
						.collect(Collectors.toUnmodifiableSet()))
				.orElse(ICodeScanner.DEFAULT_EXCLUDED_FOLDERS);
	}

	/**
	 * Get the directory that this scan agent should scan against
	 * 
	 * @return a Path to a directory containing all data that should be scanned, or null if any
	 *         problem occurred
	 */
	public Path getWorkingDirectory() {
		return this.workingDirectory;
	}

	/**
	 * Do any necessary reporting given the raw reports from the scanners
	 * 
	 * @param reports a list of reports given by the scanners
	 */
	protected abstract void report(List<CodeScanReport> reports);


	/**
	 * Do any cleanup necessary to close this scan agent. This always runs.
	 */
	protected abstract void clean();
}
