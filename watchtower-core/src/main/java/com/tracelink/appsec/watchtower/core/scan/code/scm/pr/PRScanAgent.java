package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

import java.io.File;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.FileVisitor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.zip.ZipFile;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import com.tracelink.appsec.watchtower.core.alerting.AlertService;
import com.tracelink.appsec.watchtower.core.exception.ScanInitializationException;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.module.scanner.ScanScope;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.AbstractCodeScanAgent;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.ScannerFileTypes;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanExecutionSnapshot;
import com.tracelink.appsec.watchtower.core.scan.code.SourceTreeCleaner;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanError;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.SecureZipUtils;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanAlerts.ScmAction;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.ActiveBypass;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PRScanBypassService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.data.DiffFile;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestSyncSettingsEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PullRequestSyncSettingsService;
import com.tracelink.appsec.watchtower.core.scan.queue.SqsScanQueueService;
import com.tracelink.appsec.watchtower.core.scan.storage.S3Service;
import com.tracelink.appsec.watchtower.core.exception.RateLimitedException;

/**
 * Handles scanning via SCM. downloads files from SCM and also processes violations by checking if a
 * violation is new
 *
 * @author csmith, mcool
 */
public class PRScanAgent extends
		AbstractCodeScanAgent<PRScanAgent> {
	private static Logger LOG = LoggerFactory.getLogger(PRScanAgent.class);

	private PullRequest pullRequest;
	private com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService remoteAssessments;
	private boolean remoteSelected;
	private boolean duplicateRemoteLocalResult;
	public PRScanAgent withRemoteAssessments(com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService service) {
		remoteAssessments = service; return this;
	}
	private long startTime;
	private long scanStartedNanos;
	private long submittedAt;
	private long sourceSizeBytes;
	private long sourcePreparationDurationMs;
	private long scannerExecutionDurationMs;
	private long persistenceDurationMs;
	private long savedScanId;
	private ScanScope scanScope = ScanScope.CHANGED_FILES;
	private Set<String> excludedFolders = ICodeScanner.DEFAULT_EXCLUDED_FOLDERS;
	private String sourceStrategy = "UNKNOWN";
	private final List<PRScanTimings.ScannerTiming> scannerTimings = new ArrayList<>();

	private IScmApi api;
	private PRScanResultService prScanResultService;
	private S3Service s3Service;
	private String sqsReceiptHandle;
	private SqsScanQueueService sqsScanQueueService;
	private PullRequestSyncSettingsService prSettingsService;
	private AlertService alertService;
	private PRScanBypassService bypassService;
	private String publicUrl;
	/** The PR bypass that stopped at least one finding blocking this scan, or null. */
	private ActiveBypass appliedBypass;
	/** Display names of sensitive scanners that reported errors, so their scan is incomplete. */
	private final Set<String> incompleteSensitiveScanners = new LinkedHashSet<>();
	/**
	 * Display names of every scanner that reported errors. Sensitive ones also alert; all of them
	 * are named on the pull request, which must not read as clean while a scanner did not finish.
	 */
	private final Set<String> erroredScanners = new LinkedHashSet<>();

	/**
	 * Every file changed in this pull request, mapped to its {@link DiffFile}. Fetched once in
	 * {@link #collectFiles()} (item 2.5 of IMPROVEMENT_PLAN.md) and reused by
	 * {@link #identifyNewViolations(List)} (item 2.6) and {@link #createScanConfig()}
	 * (item 2.7), replacing what used to be a separate {@code api.getGitDiffFile()} call per
	 * violated file after the scan completed.
	 * <p>
	 * Package-private, not private: {@code PRScanAgentTest} assigns it directly to exercise
	 * {@link #identifyNewViolations(List)} without going through the full
	 * {@link #initialize()} / {@link #collectFiles()} lifecycle.
	 */
	Map<String, DiffFile> changedFileDiffs = Collections.emptyMap();

	public PRScanAgent(PullRequest pullRequest) {
		super(pullRequest.getPRString());
		this.pullRequest = pullRequest;
		this.submittedAt = pullRequest.getSubmitTime();
	}

	public PRScanAgent withSubmittedAt(long submittedAt) {
		this.submittedAt = submittedAt;
		return this;
	}

	/**
	 * Set the {@linkplain IScmApi} for this Agent's configuration to interact with Pull Request
	 * SCMs
	 * 
	 * @param api the api to use
	 * @return this agent
	 */
	public PRScanAgent withApi(IScmApi api) {
		this.api = api;
		return this;
	}

	/**
	 * Set the {@linkplain AlertService} used to report incomplete scans and failed SCM calls.
	 * Optional; without it nothing is alerted.
	 *
	 * @param alertService the alert service to use
	 * @return this agent
	 */
	public PRScanAgent withAlertService(AlertService alertService) {
		this.alertService = alertService;
		return this;
	}

	/**
	 * Set the {@linkplain PRScanBypassService} that says which blocking findings a privileged
	 * user has bypassed on this pull request. Optional; without it every blocking finding blocks.
	 *
	 * @param bypassService the bypass service to use
	 * @return this agent
	 */
	public PRScanAgent withBypassService(PRScanBypassService bypassService) {
		this.bypassService = bypassService;
		return this;
	}

	/**
	 * Set Watchtower's external base URL, so the PR comment can link to the report. Optional;
	 * without it the comment has no link.
	 *
	 * @param publicUrl the base URL ({@code watchtower.publicUrl}), may be blank
	 * @return this agent
	 */
	public PRScanAgent withPublicUrl(String publicUrl) {
		this.publicUrl = publicUrl;
		return this;
	}


	/**
	 * Set the {@linkplain PRScanResultService} for this Agent's configuration
	 * 
	 * @param prScanResultService the result Service to use
	 * @return this agent
	 */
	public PRScanAgent withScanResultService(PRScanResultService prScanResultService) {
		this.prScanResultService = prScanResultService;
		return this;
	}

	/**
	 * Set the {@linkplain S3Service} used for the {@link ScanScope#FULL_SOURCE}
	 * source-zip cache (IMPROVEMENT_PLAN.md item 3.3). Optional: when not set,
	 * {@link #collectFiles()} falls back to downloading from the SCM directly, same as
	 * before this item existed - so existing callers/tests that never set this are
	 * unaffected, and a {@code S3Service} in no-op mode (no bucket configured) behaves
	 * identically to not setting this at all.
	 *
	 * @param s3Service the S3 source-zip cache to use
	 * @return this agent
	 */
	public PRScanAgent withS3Service(S3Service s3Service) {
		this.s3Service = s3Service;
		return this;
	}

	/**
	 * Set the SQS receipt handle this scan was dequeued with (IMPROVEMENT_PLAN.md item
	 * 4.7), if any. Set only by {@code SqsScanConsumer} for a scan it polled off SQS;
	 * every other construction path (the webhook/manual-submit/downtime-recovery
	 * paths, none of which go through SQS) leaves this null, which
	 * {@link #handleScanException(Exception)} treats as "there is nothing to
	 * re-enqueue" and falls through to the default failure handling.
	 *
	 * @param sqsReceiptHandle the receipt handle to requeue with on a rate limit, or
	 *                         null
	 * @return this agent
	 */
	public PRScanAgent withSqsReceiptHandle(String sqsReceiptHandle) {
		this.sqsReceiptHandle = sqsReceiptHandle;
		return this;
	}

	/**
	 * Set the {@linkplain SqsScanQueueService} used to re-enqueue this scan on a
	 * Bitbucket rate limit (IMPROVEMENT_PLAN.md item 4.7). Only meaningful together
	 * with {@link #withSqsReceiptHandle(String)}; see that method for when it applies.
	 *
	 * @param sqsScanQueueService the queue service to requeue through
	 * @return this agent
	 */
	public PRScanAgent withSqsScanQueueService(SqsScanQueueService sqsScanQueueService) {
		this.sqsScanQueueService = sqsScanQueueService;
		return this;
	}

	/**
	 * Set the {@linkplain PullRequestSyncSettingsService} used to read the admin-configured
	 * changed-file count threshold that {@link #fetchChangedFiles()} compares
	 * {@code changedFileDiffs.size()} against. Optional: when not set, the threshold is
	 * treated as unbounded and {@link #fetchChangedFiles()} always fetches one file at a
	 * time, exactly as before this setting existed - so existing callers/tests that never
	 * set this are unaffected.
	 *
	 * @param prSettingsService the settings service to read the threshold from
	 * @return this agent
	 */
	public PRScanAgent withPullRequestSyncSettingsService(
			PullRequestSyncSettingsService prSettingsService) {
		this.prSettingsService = prSettingsService;
		return this;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void initialize() throws ScanInitializationException {
		this.scanStartedNanos = System.nanoTime();
		this.startTime = System.currentTimeMillis();
		super.initialize();
		if (api == null) {
			throw new ScanInitializationException(
					"API must be configured.");
		}

		if (prScanResultService == null) {
			throw new ScanInitializationException(
					"Results Service must be configured.");
		}

		long sourcePreparationStartedNanos = System.nanoTime();
		remoteSelected = remoteAssessments != null && remoteAssessments.selected(getRuleset());
		postStatus(PRStatusComment.Phase.STARTED, null, null);
		if (remoteSelected) {
			remoteAssessments.preparePullRequest(pullRequest, getRuleset(), startTime);
			if (prScanResultService.remoteParentHasLocalResults(pullRequest.getExecutionScanId())) {
				duplicateRemoteLocalResult = true; return;
			}
			withScanners(getScanners().stream().filter(s -> s.getExecutionCapability()
					!= com.tracelink.appsec.watchtower.core.module.scanner.ExecutionCapability.REMOTE_SERVICE).toList());
		}
		// Connectivity is already proven: PRScanningService.doPullRequestScan() called
		// api.updatePRData() on the same /pullrequests/{id} endpoint moments before queuing
		// this agent, and a failure there rejects the scan before it reaches this point.
		collectFiles();

		// Captured here, not in report(), because clean() deletes the working directory
		// before report() would otherwise get a chance to measure it.
		this.sourceSizeBytes = FileUtils.sizeOfDirectory(getWorkingDirectory().toFile());
		LOG.debug("Source size for " + getScanName() + ": " + sourceSizeBytes + " bytes");
		if (getMeterRegistry() != null) {
			getMeterRegistry().summary("watchtower.scan.source_size_bytes").record(sourceSizeBytes);
		}
		this.sourcePreparationDurationMs = elapsedMillis(sourcePreparationStartedNanos);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String getMetricType() {
		return "pr";
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * Adds the set of files changed in this pull request (item 2.7 of IMPROVEMENT_PLAN.md) on
	 * top of the base config, for scanners that want finer-grained control than their declared
	 * {@link ScanScope} provides.
	 */
	@Override
	protected CodeScanConfig createScanConfig() {
		CodeScanConfig config = super.createScanConfig();
		config.setChangedFilePaths(changedFileDiffs.keySet());
		config.setRepositoryName(pullRequest.getRepoName());
		return config;
	}

	@Override
	protected List<CodeScanReport> scan() {
		if (duplicateRemoteLocalResult) return List.of();
		long startedNanos = System.nanoTime();
		try {
			return super.scan();
		} finally {
			this.scannerExecutionDurationMs = elapsedMillis(startedNanos);
		}
	}

	@Override
	protected CodeScanReport executeScanner(ICodeScanner scanner, CodeScanConfig config) {
		long startedNanos = System.nanoTime();
		try {
			CodeScanReport report = super.executeScanner(scanner, config);
			if (report != null && !report.getErrors().isEmpty()) {
				String name = CodeScanExecutionSnapshot.scannerName(scanner)
						.substring(CodeScanExecutionSnapshot.scannerName(scanner).lastIndexOf('.') + 1)
						.replaceFirst("Scanner$", "");
				// The comment names scanners as the app does ("ESLint", not the class's "EsLint")
				erroredScanners.add(com.tracelink.appsec.watchtower.core.scan.presentation.ScannerIdentity.of(name).name());
				if (scanner.isSensitive()) {
					incompleteSensitiveScanners.add(name);
				}
			}
			return report;
		} finally {
			scannerTimings.add(new PRScanTimings.ScannerTiming(
					CodeScanExecutionSnapshot.scannerName(scanner), elapsedMillis(startedNanos)));
		}
	}


	/**
	 * {@inheritDoc}
	 * <p>
	 * The implementation of report for SCM is to create database artifacts of this scan, identify
	 * if any violations are new or are blocking, and send a report to the attached SCM before
	 * saving all results
	 */
	@Override
	protected void report(List<CodeScanReport> reports) {
		if (duplicateRemoteLocalResult) return;
		long resultProcessingStartedNanos = System.nanoTime();
		List<PullRequestViolationEntity> violations = new ArrayList<>();
		List<CodeScanError> errors = new ArrayList<CodeScanError>();
		for (CodeScanReport report : reports) {
			report.getViolations().stream().forEach(sv -> {
				PullRequestViolationEntity ve =
						new PullRequestViolationEntity(sv, getWorkingDirectory());
				ve.setBypassed(false);
				RulesetDto ruleset = getRuleset();
				if (ve.getEffectiveBlocking() == null && sv.getSeverity() != null) {
					ve.setEffectiveBlocking(ruleset.getBlockingLevel() != null
							&& sv.getSeverity().compareTo(ruleset.getBlockingLevel()) <= 0);
				}
				if (ve.getEffectiveBlocking() != null) {
					ve.setBlocking(ve.getEffectiveBlocking());
				}
				violations.add(ve);
			});
			errors.addAll(report.getErrors());
		}

		// Identify violations that are new
		identifyNewViolations(violations);
		applyBypass(violations);

		Collections.sort(violations);
		long resultProcessingDurationMs = elapsedMillis(resultProcessingStartedNanos);

		long scmReportingStartedNanos = System.nanoTime();
		reportToSCM(violations, errors);
		long scmReportingDurationMs = elapsedMillis(scmReportingStartedNanos);

		// The PullRequest was fully populated by updatePRData() at queue entry, so it
		// needs no second fetch here. Re-fetching cost one Bitbucket call per scan and
		// only risked picking up a mid-scan edit.
		PRScanTimings timings = new PRScanTimings(Math.max(0, startTime - submittedAt),
				elapsedMillis(scanStartedNanos), this.sourcePreparationDurationMs,
				this.scannerExecutionDurationMs, resultProcessingDurationMs,
				scmReportingDurationMs, 0, 0, changedFileDiffs.size(), scanScope.name(),
				sourceStrategy, scannerTimings, false);
		long persistenceStartedNanos = System.nanoTime();
		this.savedScanId = prScanResultService.savePullRequestScan(pullRequest, this.startTime,
				violations, errors, this.sourceSizeBytes, timings, getExecutionSummary());
		this.persistenceDurationMs = elapsedMillis(persistenceStartedNanos);
		recordShadowComparison("pull_request", this.savedScanId);
	}

	/**
	 * A new blocking finding that an active PR bypass covers (same rule and file) stops blocking.
	 * It is still saved and reported, marked as bypassed. The bypasses are only read when
	 * something would block.
	 *
	 * @param violations this scan's violations, with their new and blocking flags set
	 */
	private void applyBypass(List<PullRequestViolationEntity> violations) {
		if (bypassService == null || violations.stream().noneMatch(PRScanAgent::blocksNew)) {
			return;
		}
		Optional<ActiveBypass> active = bypassService.activeFor(pullRequest.getApiLabel(),
				pullRequest.getRepoName(), pullRequest.getPrId());
		if (active.isEmpty()) {
			return;
		}
		for (PullRequestViolationEntity v : violations) {
			if (blocksNew(v) && active.get().covers(v.getViolationName(), v.getFileName())) {
				v.setBlocking(false);
				v.setBypassed(true);
				appliedBypass = active.get();
			}
		}
	}

	private static boolean blocksNew(PullRequestViolationEntity v) {
		return v.isBlocking() && v.isNewViolation();
	}

	private long elapsedMillis(long startedNanos) {
		if (startedNanos == 0) {
			return 0;
		}
		return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedNanos);
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * When Bitbucket's rate limiter can't be satisfied by
	 * {@code BBCloudApi}'s own bounded blocking retry (IMPROVEMENT_PLAN.md item 4.7),
	 * {@code getChangedFilesForPullRequest()}/{@code downloadFileAtCommit()} throw a
	 * {@link RateLimitedException} instead of giving up. If this scan was dequeued
	 * from SQS (both {@link #withSqsReceiptHandle(String)} and
	 * {@link #withSqsScanQueueService(SqsScanQueueService)} were set), re-enqueue it
	 * with the delay Bitbucket asked for instead of losing it - freeing this scan
	 * thread immediately rather than blocking it further. Every other case (not rate
	 * limited, not SQS-backed, or the requeue call itself fails) falls through to the
	 * default handling: the message's own visibility timeout will still redeliver it
	 * eventually even if the requeue call fails, just later and without the delay
	 * Bitbucket asked for.
	 */
	@Override
	protected void handleScanException(Exception e) {
		if (e instanceof RateLimitedException && sqsReceiptHandle != null
				&& sqsScanQueueService != null) {
			int delaySeconds = ((RateLimitedException) e).getRetryAfterSeconds();
			if (sqsScanQueueService.requeue(sqsReceiptHandle, delaySeconds)) {
				LOG.warn("Rate limited by Bitbucket while scanning " + getScanName()
						+ "; re-enqueued with " + delaySeconds
						+ "s delay for a fresh attempt instead of failing the scan.");
				return;
			}
			LOG.warn("Failed to re-enqueue rate-limited scan " + getScanName()
					+ "; its message's normal visibility timeout will redeliver it instead.");
		}
		super.handleScanException(e);
	}

	@Override
	protected void clean() {
		long cleanupStartedNanos = System.nanoTime();
		FileUtils.deleteQuietly(getWorkingDirectory().toFile());
		long cleanupDurationMs = elapsedMillis(cleanupStartedNanos);
		if (savedScanId > 0) {
			try {
				prScanResultService.finalizePerformance(savedScanId,
						elapsedMillis(scanStartedNanos), persistenceDurationMs,
						cleanupDurationMs, System.currentTimeMillis());
			} catch (RuntimeException e) {
				LOG.warn("Scan completed, but performance timing could not be finalized for "
						+ getScanName(), e);
			}
		}
	}

	/**
	 * Bytes of SHA-256 kept in a non-default source cache key's exclusion fingerprint - 64 bits,
	 * ample for telling apart the handful of exclusion sets real scanners declare.
	 */
	private static final int EXCLUSION_FINGERPRINT_BYTES = 8;

	/**
	 * Name prefix identifying a Malicious Code Review finding.
	 * <p>
	 * Produced by {@code RegexDesignerController} in the regex module, which prefixes
	 * MCR rule names with {@code "MCR Match: "} - note the trailing space, which this
	 * constant deliberately omits so that matching stays identical to the three separate
	 * string literals it replaced.
	 */
	private static final String MCR_NAME_PREFIX = "MCR Match:";

	/**
	 * How many lines either side of a modified line an MCR finding may sit and still be
	 * considered relevant to the pull request. A malicious-code pattern matters when it
	 * appears near modified code, not only on the modified line itself.
	 */
	private static final int MCR_LINE_RANGE = 5;

	private static boolean isMcrViolation(PullRequestViolationEntity violation) {
		return violation.getViolationName().startsWith(MCR_NAME_PREFIX);
	}

	/**
	 * Gather all needed files and copy them into the target directory.
	 * <p>
	 * Fetches only as much of the repository as the configured scanners actually need
	 * (item 2.5 of IMPROVEMENT_PLAN.md): the changed-file diff is always fetched, since
	 * {@link #identifyNewViolations(List)} needs it regardless of scope, but the source files
	 * themselves are fetched one at a time for {@link ScanScope#CHANGED_FILES} rather than
	 * downloading the full repository zip.
	 *
	 * @throws ScanInitializationException if there are no files to scan
	 */
	private void collectFiles() throws ScanInitializationException {
		Map<String, DiffFile> diffs = api.getChangedFilesForPullRequest(pullRequest);
		changedFileDiffs = diffs == null ? Collections.emptyMap() : diffs;

		this.scanScope = determineRequiredScope();
		this.excludedFolders = determineExcludedFolders();
		switch (scanScope) {
			case CHANGED_FILES:
				fetchChangedFiles();
				break;
			case FULL_SOURCE:
				// The S3 source-zip cache (IMPROVEMENT_PLAN.md item 3.3) only applies to
				// this branch, not MANIFEST_FILES below - no scanner currently declares
				// FULL_SOURCE (see 2.8), so this is inert until one does, exactly as the
				// plan intends.
				fetchFullSourceWithS3Cache();
				break;
			case MANIFEST_FILES:
				fetchManifestFilesOnly();
				break;
			default:
				downloadFullSourceAndClean();
				break;
		}
	}

	/**
	 * The widest {@link ScanScope} any configured scanner declares. A scanner (or a test
	 * double) that returns null is treated as {@link ScanScope#CHANGED_FILES}, matching
	 * {@code ICodeScanner.getRequiredScope()}'s own documented default.
	 *
	 * @return the scope this scan must fetch source material at
	 */
	private ScanScope determineRequiredScope() {
		ScanScope widest = ScanScope.CHANGED_FILES;
		Collection<ICodeScanner> scanners = getScanners();
		if (scanners != null) {
			for (ICodeScanner scanner : scanners) {
    if (scanner.isDisabled() || !appliesToChangedFiles(fileTypesOf(scanner))) continue;
				if (scopeRank(scanner.getRequiredScope()) > scopeRank(widest)) {
					widest = scanner.getRequiredScope();
				}
			}
		}
		return widest;
	}

	/**
	 * Ranks scopes from narrowest to widest fetch. Deliberately independent of
	 * {@link ScanScope}'s declaration order (an enum's ordinal is not a contract) and of null,
	 * which a scanner that does not override {@code getRequiredScope()} on a test double may
	 * return.
	 *
	 * @param scope the scope to rank, or null
	 * @return 0 for {@code CHANGED_FILES} or null, 1 for {@code MANIFEST_FILES}, 2 for
	 *         {@code FULL_SOURCE}
	 */
	private static int scopeRank(ScanScope scope) {
		if (scope == null) {
			return 0;
		}
		switch (scope) {
			case FULL_SOURCE:
				return 2;
			case MANIFEST_FILES:
				return 1;
			case CHANGED_FILES:
			default:
				return 0;
		}
	}

	/**
	 * Fetches the source for {@link ScanScope#CHANGED_FILES}: one Bitbucket call per changed
	 * file ({@link #fetchChangedFilesOnly()}), unless the pull request touched more files
	 * than the admin-configured threshold ({@link PullRequestSyncSettingsService#getSettings()}'s
	 * {@code fullSourceFileThreshold}) - in that case a single full-repository download
	 * (through the same S3 cache {@link ScanScope#FULL_SOURCE} scans use) is cheaper than one
	 * request per file, so this downloads everything and then deletes whatever is not a
	 * changed file, leaving the working directory - and every scanner's view of it -
	 * identical to what {@link #fetchChangedFilesOnly()} alone would have produced.
	 *
	 * @throws ScanInitializationException if the full-download fallback cannot download or
	 *                                      prune the source
	 */
	private void fetchChangedFiles() throws ScanInitializationException {
		int threshold = Integer.MAX_VALUE;
		if (prSettingsService != null) {
			PullRequestSyncSettingsEntity settings = prSettingsService.getSettings();
			if (settings != null) {
				threshold = settings.getFullSourceFileThreshold();
			}
		}
		if (changedFileDiffs.size() <= threshold) {
			sourceStrategy = "INDIVIDUAL_FILES";
			fetchChangedFilesOnly();
			return;
		}
		LOG.debug(getScanName() + " touched " + changedFileDiffs.size()
				+ " file(s), over the configured threshold of " + threshold
				+ "; downloading the full repository instead of fetching files individually");
		fetchFullSourceWithS3Cache();
		pruneToChangedFiles();
		sourceStrategy = sourceStrategy + "_PRUNED";
	}

	/**
	 * Deletes every file under {@link #getWorkingDirectory()} that is not a key of
	 * {@link #changedFileDiffs}, plus any directory left empty by that deletion. Used only
	 * after {@link #fetchFullSourceWithS3Cache()} downloads the full repository as
	 * {@link #fetchChangedFiles()}'s large-changeset fallback - the scan still only needs the
	 * changed files, the full download was purely to save Bitbucket requests.
	 *
	 * @throws ScanInitializationException if the working directory cannot be walked
	 */
	private void pruneToChangedFiles() throws ScanInitializationException {
		Path root = getWorkingDirectory();
		try {
			Files.walkFileTree(root, new SimpleFileVisitor<Path>() {
				@Override
				public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
					String relativePath =
							root.relativize(file).toString().replace(File.separatorChar, '/');
					if (!changedFileDiffs.containsKey(relativePath)) {
						FileUtils.deleteQuietly(file.toFile());
					}
					return FileVisitResult.CONTINUE;
				}

				@Override
				public FileVisitResult postVisitDirectory(Path dir, IOException exc) {
					if (!dir.equals(root)) {
						String[] remaining = dir.toFile().list();
						if (remaining != null && remaining.length == 0) {
							FileUtils.deleteQuietly(dir.toFile());
						}
					}
					return FileVisitResult.CONTINUE;
				}
			});
		} catch (IOException e) {
			throw new ScanInitializationException(
					"Failed to prune full-source download to changed files", e);
		}
	}

	/**
	 * Fetches only the files listed in {@link #changedFileDiffs}, one at a time. A single
	 * file's fetch failing (a transient error, or the file already gone by the time it is
	 * fetched) does not abort the scan - the scanners simply will not see that one file,
	 * mirroring how {@link com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBCloudApi#downloadFileAtCommit}
	 * already treats a 404 as non-fatal.
	 */
	private void fetchChangedFilesOnly() {
		for (String path : changedFileDiffs.keySet()) {
			try {
				api.downloadFileAtCommit(pullRequest, path, getWorkingDirectory());
			} catch (IOException e) {
				LOG.warn("Could not fetch " + path + " for " + pullRequest.getPRString()
						+ "; scanners will not see this file", e);
			}
		}
	}

	/**
	 * Fetches the changed files (as {@link #fetchChangedFilesOnly()} does) plus every
	 * file in the repository matching a {@link ScanScope#MANIFEST_FILES} scanner's
	 * declared patterns (IMPROVEMENT_PLAN.md item 2.5b), regardless of whether it
	 * changed in this pull request - e.g. sibling Terraform files
	 * {@link com.tracelink.appsec.module.checkov.scanner.CheckovScanner} needs to
	 * resolve references even when only one of them changed.
	 * <p>
	 * A scan can mix a {@code MANIFEST_FILES} scanner with {@code CHANGED_FILES}
	 * scanners in the same ruleset, so the changed files still need fetching here too -
	 * this branch is not exclusive with {@link #fetchChangedFilesOnly()}, just wider.
	 *
	 * @throws ScanInitializationException if the full-source fallback (taken when the
	 *                                      directory listing fails) cannot download
	 */
	private void fetchManifestFilesOnly() throws ScanInitializationException {
		sourceStrategy = "MANIFEST_FILES";
		List<String> allFiles = api.listFilesAtCommit(pullRequest);
		if (allFiles.isEmpty()) {
			// Ambiguous by design (see IScmApi.listFilesAtCommit's javadoc): a genuinely
			// empty repository looks identical to a failed listing call. Falling back to
			// a full download is always correct, just less efficient - silently treating
			// this as "no manifest files matched" risks the exact false negative
			// IMPROVEMENT_PLAN.md item 2.8 warns about.
			LOG.debug("listFilesAtCommit() returned no files for " + pullRequest.getPRString()
					+ "; falling back to full source download");
			downloadFullSourceAndClean();
			return;
		}

		fetchChangedFilesOnly();

		List<PathMatcher> matchers = collectManifestPatterns().stream()
				.flatMap(pattern -> expandGlobPattern(pattern).stream())
				.map(pattern -> FileSystems.getDefault().getPathMatcher("glob:" + pattern))
				.collect(Collectors.toList());
		for (String path : allFiles) {
			if (changedFileDiffs.containsKey(path)) {
				// Already fetched by fetchChangedFilesOnly() above.
				continue;
			}
			Path relativePath = Paths.get(path);
			boolean matchesManifestPattern =
					matchers.stream().anyMatch(matcher -> matcher.matches(relativePath));
			if (matchesManifestPattern) {
				try {
					api.downloadFileAtCommit(pullRequest, path, getWorkingDirectory());
				} catch (IOException e) {
					LOG.warn("Could not fetch manifest file " + path + " for "
							+ pullRequest.getPRString() + "; scanners will not see this file", e);
				}
			}
		}
	}

	/**
	 * Expands a {@code "**&#47;foo"} pattern to also match a file at the repository
	 * root with no preceding directory. The JDK's {@link PathMatcher} {@code **}
	 * component requires at least one path separator to have matched something, so
	 * {@code "**&#47;*.tf"} alone silently skips a root-level {@code main.tf} - exactly
	 * the false negative this item exists to avoid (and one that affects every
	 * scanner's patterns declared this way, including
	 * {@code CheckovScanner.getRequiredFilePatterns()}'s own {@code "**&#47;*.tf"}).
	 *
	 * @param pattern a glob pattern as declared by
	 *                {@code ICodeScanner.getRequiredFilePatterns()}
	 * @return the pattern, plus its root-level equivalent if it started with
	 *         {@code "**&#47;"}
	 */
	private static List<String> expandGlobPattern(String pattern) {
		if (pattern.startsWith("**/")) {
			return Arrays.asList(pattern, pattern.substring(3));
		}
		return Collections.singletonList(pattern);
	}

	/**
	 * Whether a scanner with these file types has something reportable in this pull request. A
	 * pull request only reports findings in files it changed, so a scanner with no changed file of
	 * its types is not run and does not widen what is fetched. The same answer drives the scope,
	 * the manifest patterns and the decision to run. Unknown changed files fail open.
	 *
	 * @param types the scanner's file types; empty or null means every file
	 * @return true if the scanner may have something to report
	 */
	private boolean appliesToChangedFiles(List<String> types) {
		try {
			if (types == null || types.isEmpty() || changedFileDiffs == null || changedFileDiffs.isEmpty()) {
				return true;
			}
			return ScannerFileTypes.anyMatch(types, changedFileDiffs.keySet());
		} catch (RuntimeException e) {
			return true;
		}
	}

	@Override
	protected boolean hasFileOfType(List<String> types, CodeScanConfig config) {
		return appliesToChangedFiles(types);
	}

	/**
	 * @return the union of {@code getRequiredFilePatterns()} from every configured
	 *         scanner that declares {@link ScanScope#MANIFEST_FILES}
	 */
	private Set<String> collectManifestPatterns() {
		Collection<ICodeScanner> scanners = getScanners();
		if (scanners == null) {
			return Collections.emptySet();
		}
		return scanners.stream()
				.filter(scanner -> !scanner.isDisabled() && appliesToChangedFiles(fileTypesOf(scanner)))
				.filter(scanner -> scanner.getRequiredScope() == ScanScope.MANIFEST_FILES)
				.flatMap(scanner -> scanner.getRequiredFilePatterns().stream())
				.collect(Collectors.toSet());
	}

	/**
	 * Downloads the complete repository source and removes folders/files no scanner needs.
	 * Exactly today's pre-2.5 {@code collectFiles()} behaviour. Always used for
	 * {@link ScanScope#MANIFEST_FILES}; used for {@link ScanScope#FULL_SOURCE} too, but
	 * only as {@link #fetchFullSourceWithS3Cache()}'s fallback when S3 is unconfigured,
	 * a cache miss occurs, or the cached zip fails to extract.
	 *
	 * @throws ScanInitializationException if the source cannot be downloaded
	 */
	private void downloadFullSourceAndClean() throws ScanInitializationException {
		sourceStrategy = "FULL_DOWNLOAD";
		try {
			api.downloadSourceForPullRequest(pullRequest, getWorkingDirectory());
			SourceTreeCleaner.clean(getWorkingDirectory(), excludedFolders);
		} catch (IOException e) {
			throw new ScanInitializationException("Could not download source", e);
		}
	}

	/**
	 * The S3-cache-aware fetch for {@link ScanScope#FULL_SOURCE} (IMPROVEMENT_PLAN.md
	 * item 3.3): a cache hit extracts the cached zip directly; a cache miss (or a
	 * missing/failing {@link S3Service}) falls back to
	 * {@link #downloadFullSourceAndClean()} exactly as before this item existed, then
	 * caches the result for next time. S3 is a cache, not a hard dependency - a read or
	 * write failure never fails the scan, it just means this run does the same work a
	 * FULL_SOURCE scan always did.
	 *
	 * @throws ScanInitializationException if the source cannot be downloaded (only
	 *                                      reachable via the fallback download, not via
	 *                                      a cache failure)
	 */
	private void fetchFullSourceWithS3Cache() throws ScanInitializationException {
		if (s3Service == null || !s3Service.isEnabled()) {
			downloadFullSourceAndClean();
			return;
		}

		String cacheKey = buildSourceCacheKey();
		if (tryExtractFromCache(cacheKey)) {
			sourceStrategy = "CACHED_ARCHIVE";
			LOG.debug("Source cache hit for " + getScanName() + " at " + cacheKey);
			return;
		}

		downloadFullSourceAndClean();
		cacheSourceAsync(cacheKey);
	}

	/**
	 * @param cacheKey the S3 key to read
	 * @return true if the key existed and its contents were extracted into the working
	 *         directory (already the cleaned shape {@link #downloadFullSourceAndClean()}
	 *         would have produced, since that is what gets cached - see
	 *         {@link #cacheSourceAsync(String)}); false on any cache miss or failure, in
	 *         which case the working directory is left empty for the caller's normal
	 *         download to populate
	 */
	private boolean tryExtractFromCache(String cacheKey) {
		Path tempZip = null;
		try {
			tempZip = Files.createTempFile("source-cache-", ".zip");
			if (!s3Service.downloadZip(cacheKey, tempZip)) {
				return false;
			}
			SecureZipUtils.secureUnzip(new ZipFile(tempZip.toFile()), getWorkingDirectory().toFile());
			return true;
		} catch (IOException e) {
			LOG.warn("Failed to extract cached source for " + getScanName() + " from " + cacheKey
					+ "; falling back to a direct download", e);
			FileUtils.deleteQuietly(getWorkingDirectory().toFile());
			return false;
		} finally {
			if (tempZip != null) {
				FileUtils.deleteQuietly(tempZip.toFile());
			}
		}
	}

	/**
	 * Zips the just-downloaded, just-cleaned working directory and uploads it to the S3
	 * cache. The zip is built synchronously (a local disk walk, same order of cost as
	 * the cleanup {@link #downloadFullSourceAndClean()} already just did) but the upload
	 * itself - the slow, unreliable part - runs off-thread so a slow or failing S3 write
	 * never delays {@code report()}. Building the zip only from
	 * {@code getWorkingDirectory()}'s current top-level children, rather than the
	 * directory itself, keeps every entry's path relative to the working directory root
	 * - matching what {@link #tryExtractFromCache(String)} expects when it later
	 * extracts into a fresh working directory.
	 *
	 * @param cacheKey the S3 key to write
	 */
	private void cacheSourceAsync(String cacheKey) {
		File[] children = getWorkingDirectory().toFile().listFiles();
		if (children == null) {
			return;
		}
		Path tempZip;
		try {
			tempZip = Files.createTempFile("source-cache-", ".zip");
			Files.delete(tempZip);
			net.lingala.zip4j.ZipFile zip = new net.lingala.zip4j.ZipFile(tempZip.toFile());
			for (File child : children) {
				if (child.isDirectory()) {
					zip.addFolder(child);
				} else {
					zip.addFile(child);
				}
			}
		} catch (IOException e) {
			LOG.warn("Failed to build source cache zip for " + getScanName(), e);
			return;
		}
		Path finalTempZip = tempZip;
		CompletableFuture.runAsync(() -> {
			try {
				s3Service.uploadZip(cacheKey, finalTempZip);
			} finally {
				FileUtils.deleteQuietly(finalTempZip.toFile());
			}
		});
	}

	/**
	 * @return the S3 key for this pull request's commit, per IMPROVEMENT_PLAN.md's
	 *         {@code source/{workspace}/{repo}/{commitHash}.zip} scheme.
	 *         {@link PullRequest} has no separate "workspace" field distinct from
	 *         apiLabel - Bitbucket's workspace concept lives on
	 *         {@code BBCloudIntegrationEntity}, not on {@code PullRequest} - and
	 *         apiLabel already uniquely identifies which integration/workspace owns
	 *         this repo, the same substitution
	 *         {@code PRScanningService.buildDedupKey()} already makes for its own key.
	 */
	private String buildSourceCacheKey() {
		return sourceCacheKey(pullRequest.getApiLabel(), pullRequest.getRepoName(),
				pullRequest.getCommitHash(), excludedFolders);
	}

	/**
	 * The S3 key of a cached source zip. The zip holds the tree <em>after</em> excluded folders
	 * were deleted, so scans that exclude different folders must not share one. The default
	 * exclusions keep the original key, so existing cache entries stay valid; any other set
	 * gets an order-independent fingerprint suffix.
	 *
	 * @param apiLabel        the integration's label
	 * @param repoName        the repository name
	 * @param commitHash      the scanned commit
	 * @param excludedFolders the folders deleted from the cached tree
	 * @return the cache key
	 */
	static String sourceCacheKey(String apiLabel, String repoName, String commitHash,
			Set<String> excludedFolders) {
		String base = "source/" + apiLabel + "/" + repoName + "/" + commitHash;
		if (ICodeScanner.DEFAULT_EXCLUDED_FOLDERS.equals(excludedFolders)) {
			return base + ".zip";
		}
		return base + "-" + exclusionFingerprint(excludedFolders) + ".zip";
	}

	private static String exclusionFingerprint(Set<String> excludedFolders) {
		String canonical = excludedFolders.stream().sorted().collect(Collectors.joining("/"));
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256")
					.digest(canonical.getBytes(StandardCharsets.UTF_8));
			return HexFormat.of().formatHex(digest, 0, EXCLUSION_FINGERPRINT_BYTES);
		} catch (NoSuchAlgorithmException e) {
			// Every JRE is required to provide SHA-256.
			throw new IllegalStateException("SHA-256 unavailable", e);
		}
	}

	/**
	 * For each violation in the given list, determine if the violation is preexisting or new for
	 * this scan. Return the results of this determination.
	 *
	 * @param violations the violations to mark as new or preexisting
	 */
	private void identifyNewViolations(
			List<PullRequestViolationEntity> violations) {
		// Get set of files with violations, for the summary log line below.
		Set<String> violationFiles = new HashSet<>();
		violations.forEach(v -> violationFiles.add(v.getFileName()));

		// changedFileDiffs was fetched once for the whole PR in collectFiles() (item 2.6 of
		// IMPROVEMENT_PLAN.md), replacing what used to be a separate api.getGitDiffFile()
		// call per violated file here. A single bulk fetch has no per-file failure to report
		// - either the whole fetch failed and collectFiles() already aborted the scan, or it
		// returned whatever files Bitbucket reported as changed - so there is no longer a
		// "diff fetch failure" count distinct from "file not in diff".
		long changedViolationFiles = violationFiles.stream()
				.filter(f -> {
					DiffFile diff = changedFileDiffs.get(f);
					return diff != null && diff.hasDiffs();
				})
				.count();

		// Use the diff files to determine if each violation is new or preexisting
		// Use diff files to determine if MCR finding is likely relevant to the PR
		int kept = 0;
		int newViolations = 0;
		int droppedNotInDiff = 0;
		int droppedMcrOutOfRange = 0;
		Iterator<PullRequestViolationEntity> violationIter = violations.iterator();
		while (violationIter.hasNext()) {
			PullRequestViolationEntity violation = violationIter.next();
			DiffFile diff = changedFileDiffs.get(violation.getFileName());

			// We are only looking for violations that occur in files that have been modified. So
			// remove all latent violations in source code files that have nothing to do with this
			// Pull Request
			if (diff == null || !diff.hasDiffs()) {
				violationIter.remove();
				droppedNotInDiff++;
				continue;
			}
			// Remove any MCR findings that were not within range of the modified code.
			if (isMcrViolation(violation)
					&& !hasChangedLineInRange(diff, violation.getLineNum())) {
				violationIter.remove();
				droppedMcrOutOfRange++;
				continue;
			}
			boolean isNew = diff.isLineChanged(violation.getLineNum());
			violation.setNewViolation(isNew);
			kept++;
			if (isNew) {
				newViolations++;
			}
			LOG.debug("Violation " + violation.getViolationName() + " at "
					+ violation.getFileName() + ":" + violation.getLineNum()
					+ " classified as " + (isNew ? "new" : "pre-existing"));
		}

		// One line that shows whether diff-based classification is behaving: if line
		// numbers were wrong, violations would all land as pre-existing or all be
		// dropped as not-in-diff.
		LOG.info("Violation classification for " + pullRequest.getPRString() + ": "
				+ violationFiles.size() + " file(s) with violations, " + changedViolationFiles
				+ " of them changed in this Pull Request; " + kept + " violation(s) kept ("
				+ newViolations + " new, " + (kept - newViolations) + " pre-existing), "
				+ droppedNotInDiff + " dropped as not in the diff, " + droppedMcrOutOfRange
				+ " MCR dropped outside +/-" + MCR_LINE_RANGE + " lines");
	}

	/**
	 * Determines whether the pull request changed any line within
	 * {@link #MCR_LINE_RANGE} lines either side of the given line.
	 *
	 * @param diff    the diff for the file the violation was found in
	 * @param lineNum the line the violation was reported on
	 * @return true if a changed line falls within the range
	 */
	private boolean hasChangedLineInRange(DiffFile diff, int lineNum) {
		for (int i = lineNum - MCR_LINE_RANGE; i <= lineNum + MCR_LINE_RANGE; i++) {
			if (diff.isLineChanged(i)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * send a comment, and then if this scan should block based on any findings, send the block
	 * command
	 * 
	 * @param violations the list of violations found in this scan from all scanners
	 * @param errors     the list of errors found during this scan
	 */
	private void reportToSCM(List<PullRequestViolationEntity> violations,
			List<CodeScanError> errors) {
		// Live AWS enforcement remains gated on the explicit failure/timeout decision.
		// Local results are persisted promptly, but may not publish an aggregate final pass.
		if (remoteSelected) {
			postStatus(PRStatusComment.Phase.LOCAL_DONE_REMOTE_RUNNING,
					(int) violations.stream().filter(v -> !isMcrViolation(v)).count(), null);
			return;
		}
		PRScanAlerts alerts = new PRScanAlerts(alertService, getMeterRegistry());
		// MCR findings are never shown on the PR - neither inline nor in the summary, including
		// its headline - they surface through the MCR dashboard only.
		List<PullRequestViolationEntity> reported = violations.stream()
				.filter(v -> !isMcrViolation(v)).toList();
		int notInline = new PRInlineComments(api, pullRequest).sync(reported, appliedBypass,
				pullRequest.getCommitHash());
		String summary = new PRScanSummary(reported, erroredScanners, appliedBypass,
				notInline, pullRequest.getCommitHash(), reportLink(),
				api.keepsBlockedPullRequestsOpen()).toMarkdown();
		// With the status comment on, the pull request's one comment becomes this summary; otherwise it is posted on its own.
		alerts.recordScmAction(ScmAction.COMMENT, statusCommentsEnabled()
				? postStatus(PRStatusComment.Phase.FINISHED, reported.size(),
						hasBlockingViolations(violations) ? PRStatusComment.Result.BLOCKED : PRStatusComment.Result.PASSED, summary)
				: api.sendComment(pullRequest, summary));

		// Review-state calls are no-ops unless the integration opts into
		// APPROVE_OR_REQUEST_CHANGES; blockPR is a no-op unless it uses BLOCK_PR.
		// Blocking is unchanged by an incomplete scan: it fails open, as scanner errors always did.
		if (hasBlockingViolations(violations)) {
			alerts.recordScmAction(ScmAction.DECLINE, api.blockPR(pullRequest));
			alerts.recordScmAction(ScmAction.REQUEST_CHANGES, api.requestChangesPR(pullRequest));
		} else {
			alerts.recordScmAction(ScmAction.APPROVE, api.approvePR(pullRequest));
		}
		if (!errors.isEmpty()) {
			logErrors(errors);
		}
		alerts.scanIncomplete(pullRequest, incompleteSensitiveScanners);
		alerts.raiseFailedScmActions(pullRequest);
	}

	/**
	 * @return the PR's latest Watchtower report, or null without a public URL. This scan's own id
	 *         is not known yet: it is saved after the PR is commented on.
	 */
	private String reportLink() {
		return PRStatusComment.reportLink(publicUrl, pullRequest);
	}

	private boolean statusCommentsEnabled() {
		return prSettingsService != null && prSettingsService.getSettings() != null
				&& prSettingsService.getSettings().isStatusCommentsEnabled();
	}

	private void postStatus(PRStatusComment.Phase phase, Integer localFindings, PRStatusComment.Result result) {
		postStatus(phase, localFindings, result, null);
	}

	/**
	 * Keeps the pull request's one status comment in step with this scan. Off unless the PR settings turn it on (they do by default),
	 * and never allowed to affect the scan.
	 *
	 * @param summary the scan summary the comment becomes when the scan has finished, or null
	 * @return whether the comment is in step, or the settings leave it off
	 */
	private boolean postStatus(PRStatusComment.Phase phase, Integer localFindings, PRStatusComment.Result result, String summary) {
		try {
			if (!statusCommentsEnabled()) {
				return true;
			}
			return PRStatusComment.post(api, pullRequest, new PRStatusComment.Status(pullRequest.getCommitHash(), phase,
					remoteSelected, localFindings, null, null, result, reportLink(), summary));
		} catch (RuntimeException e) {
			LOG.warn("Could not update the status comment for {}", pullRequest.getPRString(), e);
			return false;
		}
	}

	private static String encode(String value) {
		return URLEncoder.encode(StringUtils.defaultString(value), StandardCharsets.UTF_8);
	}

	/**
	 * If there are any errors, this method will execute. Default implementation is to log to the
	 * debug log
	 * 
	 * @param errors the list of errors to log
	 */
	private void logErrors(List<CodeScanError> errors) {
		StringBuilder sb = new StringBuilder();
		sb.append("Errors found during scan: " + pullRequest.getPRString() + '\n');
		for (CodeScanError err : errors) {
			sb.append("--" + err.getErrorMessage() + '\n');
		}
		LOG.debug(sb.toString());
	}

	/**
	 * Determines whether any violation should block the pull request.
	 * <p>
	 * Note that this deliberately does <em>not</em> exclude MCR findings, even though
	 * {@link #buildReport(List)} omits them from the comment posted to the SCM. An MCR
	 * match at or above the ruleset's blocking level therefore declines the pull request
	 * while the comment says nothing about it, by design - MCR detail is surfaced through
	 * the MCR dashboard rather than the pull request. Reviewed and kept as-is on
	 * 2026-09-04; see IMPROVEMENT_PLAN.md item 1.13 and the MCR characterization tests in
	 * {@code PRScanAgentTest}, which will fail if this is changed.
	 *
	 * @param violations the violations found in this scan
	 * @return true if the pull request should be blocked
	 */
	private Boolean hasBlockingViolations(List<PullRequestViolationEntity> violations) {
		return violations.stream().anyMatch(v -> (v.isBlocking() && v.isNewViolation()));
	}

}
