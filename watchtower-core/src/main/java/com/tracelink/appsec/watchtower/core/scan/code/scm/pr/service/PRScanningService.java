package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service;

import ch.qos.logback.classic.Level;
import com.tracelink.appsec.watchtower.core.alerting.AlertService;
import com.tracelink.appsec.watchtower.core.exception.PullRequestNotFoundException;
import com.tracelink.appsec.watchtower.core.exception.ScanQuiescedException;
import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.logging.LogsService;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanningService;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.RepositorySlug;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanAgent;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanSubmitResult;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.ScanExecutionResult;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PRScanBypassService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.queue.ScanRequestMessage;
import com.tracelink.appsec.watchtower.core.scan.queue.SqsScanQueueService;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryService;
import com.tracelink.appsec.watchtower.core.scan.storage.S3Service;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Manages creating scans for Pull Requests
 *
 * @author csmith
 */
@Service
public class PRScanningService extends AbstractScanningService {
	@Autowired(required = false)
	private com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService remoteAssessments;
	@org.springframework.beans.factory.annotation.Autowired(required = false)
	private com.tracelink.appsec.watchtower.core.rule.candidate.RuleShadowService candidateShadow;


	private static final Logger LOG = LoggerFactory.getLogger(PRScanningService.class);

	private final LogsService logService;
	private final RepositoryService repoService;
	private final PRScanResultService prScanResultService;
	private final ScanRegistrationService scanRegistrationService;
	private final ApiIntegrationService apiService;
	private final MeterRegistry meterRegistry;
	private final Counter scanQueuedCounter;
	private final S3Service s3Service;
	private final SqsScanQueueService sqsScanQueueService;
	private final PullRequestSyncSettingsService prSettingsService;
	private final boolean sqsSubmissionEnabled;
	private AlertService alertService;
	private PRScanBypassService bypassService;
	private String publicUrl;

	/**
	 * Scans currently queued or running, keyed by {@link #buildDedupKey(PullRequest)}.
	 * Entries are removed when the scan completes, so a later rescan of the same commit
	 * is always allowed.
	 */
	private final ConcurrentHashMap<String, CompletableFuture<?>> inFlightScans =
			new ConcurrentHashMap<>();

	public PRScanningService(
			@Autowired LogsService logService,
			@Autowired RepositoryService repoService,
			@Autowired PRScanResultService prScanResultService,
			@Autowired ScanRegistrationService scanRegistrationService,
			@Autowired ApiIntegrationService apiService,
			@Autowired MeterRegistry meterRegistry,
			@Autowired S3Service s3Service,
			@Autowired SqsScanQueueService sqsScanQueueService,
			@Autowired PullRequestSyncSettingsService prSettingsService,
			@Value("${watchtower.threads.prscan:4}") int threads,
			@Value("${watchtower.runAfterStartup:true}") boolean recoverFromDowntime,
			@Value("${watchtower.queue.prscan.capacity:100}") int queueCapacity,
			@Value("${watchtower.queue.sqs.submission-enabled:false}") boolean sqsSubmissionEnabled) {
		super(threads, recoverFromDowntime, queueCapacity);
		this.logService = logService;
		this.repoService = repoService;
		this.prScanResultService = prScanResultService;
		this.scanRegistrationService = scanRegistrationService;
		this.apiService = apiService;
		this.meterRegistry = meterRegistry;
		this.s3Service = s3Service;
		this.sqsScanQueueService = sqsScanQueueService;
		this.prSettingsService = prSettingsService;
		this.sqsSubmissionEnabled = sqsSubmissionEnabled;
		this.scanQueuedCounter = Counter.builder("watchtower.scan.queued")
				.tag("type", "pr")
				.register(meterRegistry);
		Gauge.builder("watchtower.scan.queue.depth", this, PRScanningService::getTaskNumInQueue)
				.tag("type", "pr")
				.register(meterRegistry);
	}

	/**
	 * Optional: scans raise incomplete-scan and failed-SCM-call alerts through it.
	 *
	 * @param alertService the alert service
	 */
	@Autowired(required = false)
	public void setAlertService(AlertService alertService) {
		this.alertService = alertService;
	}

	/**
	 * Optional: scans stop blocking on findings a privileged user bypassed.
	 *
	 * @param bypassService the bypass service
	 */
	@Autowired(required = false)
	public void setBypassService(PRScanBypassService bypassService) {
		this.bypassService = bypassService;
	}

	/**
	 * Optional: Watchtower's external base URL, so PR comments link to the report.
	 *
	 * @param publicUrl the base URL; blank for no link
	 */
	@Value("${watchtower.publicUrl:#{null}}")
	public void setPublicUrl(String publicUrl) {
		this.publicUrl = publicUrl;
	}

	/**
	 * Confirms that a pull request named by a person exists before it is queued. With SQS the
	 * provider is otherwise not asked until the consumer picks the message up, which left a
	 * typo in the form reporting a queued scan that never appeared. Webhooks skip this: the
	 * provider has just told us the pull request exists, and a burst must not fan out into
	 * provider calls on the HTTP threads.
	 *
	 * @param pr the pull request as typed
	 * @throws ScanRejectedException if the integration cannot scan pull requests, or the
	 *                               provider says the pull request does not exist
	 */
	public void requirePullRequestExists(PullRequest pr) throws ScanRejectedException {
		ApiIntegrationEntity apiEntity = apiService.findByLabel(pr.getApiLabel());
		if (apiEntity == null || apiEntity.getScanType() != CodeScanType.PULL_REQUEST) {
			throw new ScanRejectedException("Choose an integration that supports pull request scanning.");
		}
		PullRequest probe = new PullRequest(pr.getApiLabel());
		probe.setRepoName(RepositorySlug.of(pr.getRepoName()));
		probe.setPrId(pr.getPrId());
		try {
			((IScmApi) apiEntity.createApi()).updatePRData(probe);
		} catch (PullRequestNotFoundException e) {
			throw e;
		} catch (Exception e) {
			// An unreachable provider is a reason to retry later, not to refuse the request
			LOG.warn("Could not confirm that PR " + probe.getPRString() + " exists", e);
		}
	}

	/**
	 * Queue a new Scan onto the next available async thread.
	 *
	 * @param pr an object describing the pull request to review
	 * @return the outcome of the submission, so callers can distinguish a queued scan
	 *         from one that was dropped
	 * @throws RejectedExecutionException if the async manager cannot handle another task
	 * @throws ScanQuiescedException      if the system is quiesced, which is temporary and
	 *                                    worth retrying
	 * @throws ScanRejectedException      If the scan could not be started due to a configuration
	 *                                    problem
	 */
	public PRScanSubmitResult doPullRequestScan(PullRequest pr)
			throws RejectedExecutionException, ScanRejectedException {
		// One name per repository before any key is built: the webhook, the manual form, the
		// REST API, recovery and a bypass rescan must all name the same pull request alike, or
		// the SQS group, the work item and the duplicate checks see two pull requests
		pr.setRepoName(RepositorySlug.of(pr.getRepoName()));
		String prName = pr.getPRString();
		long submittedAt = pr.getSubmitTime();
		LOG.debug("Starting PR scan for " + prName + " (apiLabel=" + pr.getApiLabel() + ")");
		if (isQuiesced()) {
			LOG.error("Quiesced. Did not schedule PR: " + prName);
			throw new ScanQuiescedException("Quiesced. Did not schedule PR: " + prName);
		}
		ApiIntegrationEntity apiEntity = apiService.findByLabel(pr.getApiLabel());
		if (apiEntity == null || apiEntity.getScanType() != CodeScanType.PULL_REQUEST) {
			throw new ScanRejectedException("Choose an integration that supports pull request scanning.");
		}
		if (sqsSubmissionEnabled && sqsScanQueueService.isEnabled()) {
			// SQS is the ingress boundary. External provider validation is
			// deliberately deferred to SqsScanConsumer so request bursts do not fan out
			// into simultaneous SCM calls on the HTTP thread.
			// What the database alone can answer is answered now. A queued message for a paused
			// repository was acknowledged as queued and then dropped without a trace.
			Optional<RepositoryEntity> known =
					repoService.findExisting(pr.getApiLabel(), pr.getRepoName());
			if (known.isPresent() && known.get().isScanningPaused()) {
				LOG.info("PR: " + prName + " skipped as scanning of the repository is paused.");
				return PRScanSubmitResult.PAUSED;
			}
			if (known.isPresent() && known.get().getRuleset() == null) {
				LOG.info("PR: " + prName
						+ " skipped as the repository is not configured with a ruleset.");
				return PRScanSubmitResult.NO_RULESET;
			}
			ScanRequestMessage message = new ScanRequestMessage(pr.getApiLabel(), pr.getRepoName(),
					pr.getPrId(), pr.getCommitHash(), System.currentTimeMillis());
			if (!sqsScanQueueService.publish(message)) {
				throw new ScanRejectedException("Could not queue scan request for " + prName);
			}
			// INFO: the only trace that a webhook arrived until the consumer picks it up, which
			// waits for startup to finish.
			LOG.info("Queued a scan of PR " + prName + " (commit " + pr.getCommitHash()
					+ ") on SQS");
			return PRScanSubmitResult.QUEUED;
		}

		RepositoryEntity repo = repoService.upsertRepo(CodeScanType.PULL_REQUEST, pr.getApiLabel(),
				pr.getRepoName());
		if (repo.isScanningPaused()) {
			LOG.info("PR: " + prName + " skipped as scanning of the repository is paused.");
			return PRScanSubmitResult.PAUSED;
		}
		RulesetEntity ruleset = repo.getRuleset();

		// Skip scan if repository is not configured with a ruleset
		if (ruleset == null) {
			LOG.info("PR: " + prName
					+ " skipped as the repository is not configured with a ruleset.");
			return PRScanSubmitResult.NO_RULESET;
		}

		// Skip scan if there are no scanners configured
		if (!scanRegistrationService.hasCodeScanners()) {
			LOG.info("PR: " + prName + " skipped as there are no scanners configured.");
			return PRScanSubmitResult.NO_SCANNERS;
		}
		LOG.debug("Found api integration for " + prName + ", fetching PR data");
		IScmApi api = (IScmApi) apiEntity.createApi();
		pr = api.updatePRData(pr);

		// A closed Pull Request needs no scan. Commenting on one is noise, and blocking
		// it fails outright - Bitbucket answers 400 to a decline on a merged PR.
		//
		// This check belongs here rather than in a controller: the webhook, the manual
		// submit form and downtime recovery all funnel through this method, and only the
		// webhook used to check. A merged PR submitted from the portal was scanned in
		// full and then had a decline attempted against it.
		if (pr.getState() != null && pr.getState().isResolved()) {
			LOG.info("PR " + prName + " is already " + pr.getState()
					+ "; resolving without scanning");
			prScanResultService.markPrResolved(pr, hasPendingScan(pr));
			return PRScanSubmitResult.ALREADY_RESOLVED;
		}

		return executeScan(pr, api, ruleset, null, submittedAt).result();
	}

	/**
	 * Same as {@link #executeScan(PullRequest, IScmApi, RulesetEntity, String)} with no
	 * SQS receipt handle - the webhook/manual-submit/downtime-recovery paths, none of
	 * which run under SQS.
	 *
	 * @param pr      the up-to-date pull request to scan
	 * @param api     the SCM API client to use for this pull request
	 * @param ruleset the ruleset to scan against
	 * @return the outcome of the submission
	 */
	public ScanExecutionResult executeScan(PullRequest pr, IScmApi api, RulesetEntity ruleset) {
		return executeScan(pr, api, ruleset, null);
	}

	/**
	 * Builds a {@linkplain PRScanAgent} for an already-validated, up-to-date Pull
	 * Request and submits it to this pod's executor, deduplicating against any
	 * identical scan already running in this process.
	 * <p>
	 * Called by {@link #doPullRequestScan(PullRequest)} itself when SQS submission is
	 * disabled or unconfigured, and by {@code SqsScanConsumer} once it has polled a
	 * message off SQS and re-run this same validation (ruleset, scanners, api lookup,
	 * fresh {@code updatePRData}, resolved-state) against current data. Never call this
	 * without having already done that validation - it assumes {@code ruleset} is
	 * non-null and {@code pr} reflects Bitbucket's current state.
	 *
	 * @param pr               the up-to-date pull request to scan
	 * @param api              the SCM API client to use for this pull request
	 * @param ruleset          the ruleset to scan against
	 * @param sqsReceiptHandle the SQS receipt handle this scan was dequeued with
	 *                         (IMPROVEMENT_PLAN.md item 4.7), or null if it wasn't
	 *                         dequeued from SQS
	 * @return the outcome of the submission, including the agent and future a caller
	 *         needs to defer action until the scan actually finishes (see
	 *         {@linkplain ScanExecutionResult})
	 */
	public ScanExecutionResult executeScan(PullRequest pr, IScmApi api, RulesetEntity ruleset,
			String sqsReceiptHandle) {
		return executeScan(pr, api, ruleset, sqsReceiptHandle, pr.getSubmitTime());
	}

	public ScanExecutionResult executeScan(PullRequest pr, IScmApi api, RulesetEntity ruleset,
			String sqsReceiptHandle, long submittedAt) {
		String prName = pr.getPRString();

		// Bitbucket delivers several events for the same push (and retries deliveries),
		// so the same commit can arrive two or three times within seconds. Each one used
		// to queue its own agent: same zip downloaded repeatedly, duplicate comments
		// posted. The key includes the commit hash, so a force-push is still a new scan.
		String dedupKey = buildDedupKey(pr);
		CompletableFuture<?> inFlight = inFlightScans.get(dedupKey);
		if (inFlight != null && !inFlight.isDone()) {
			LOG.info("Skipping PR " + prName
					+ ": an identical scan is already in flight for commit "
					+ pr.getCommitHash());
			return new ScanExecutionResult(PRScanSubmitResult.DEDUPLICATED, null, null);
		}

		LOG.debug("Fetched PR data for " + prName + ", queuing scan agent");

		// Create scan agent
		PRScanAgent scanAgent = new PRScanAgent(pr).withRemoteAssessments(remoteAssessments)
				.withSubmittedAt(submittedAt)
				.withApi(api)
				.withScanResultService(prScanResultService)
				.withCandidateShadow(candidateShadow)
				.withScanners(scanRegistrationService.getCodeScanners())
				.withRuleset(ruleset.toDto())
				.withBenchmarkEnabled(!logService.getLogsLevel().isGreaterOrEqual(Level.INFO))
				.withMeterRegistry(meterRegistry)
				.withS3Service(s3Service)
				.withSqsReceiptHandle(sqsReceiptHandle)
				.withSqsScanQueueService(sqsScanQueueService)
				.withPullRequestSyncSettingsService(prSettingsService)
				.withAlertService(alertService)
				.withBypassService(bypassService)
				.withPublicUrl(publicUrl);

		// The check above is a fast path that avoids building an agent for nothing. This
		// compute() is the authority: check and insert must be one atomic step, or two
		// simultaneous webhooks can both pass the fast path. The completion callback is
		// registered after compute() returns, because ConcurrentHashMap forbids modifying
		// the map from inside a compute function.
		AtomicReference<CompletableFuture<?>> submitted = new AtomicReference<>();
		inFlightScans.compute(dedupKey, (key, existing) -> {
			if (existing != null && !existing.isDone()) {
				return existing;
			}
			CompletableFuture<?> future = CompletableFuture.runAsync(scanAgent, getExecutor());
			submitted.set(future);
			return future;
		});

		CompletableFuture<?> future = submitted.get();
		if (future == null) {
			LOG.info("Skipping PR " + prName + ": an identical scan was queued concurrently");
			return new ScanExecutionResult(PRScanSubmitResult.DEDUPLICATED, null, null);
		}
		// Two-arg remove so a newer scan queued under the same key is never evicted.
		future.whenComplete((result, error) -> inFlightScans.remove(dedupKey, future));
		scanQueuedCounter.increment();
		return new ScanExecutionResult(PRScanSubmitResult.QUEUED, scanAgent, future);
	}

	/**
	 * Never throws: a failed lookup only means the merge gate view cannot say a scan was
	 * pending, which must not stop the pull request being resolved.
	 *
	 * @param pr a pull request the SCM just reported closed
	 * @return whether a scan of it, of any commit, is queued or running on this pod or on the
	 *         queue
	 */
	public boolean hasPendingScan(PullRequest pr) {
		String prefix = pr.getApiLabel() + "/" + pr.getRepoName() + "/" + pr.getPrId() + "/";
		boolean inFlightHere = inFlightScans.entrySet().stream()
				.anyMatch(e -> e.getKey().startsWith(prefix) && !e.getValue().isDone());
		if (inFlightHere) {
			return true;
		}
		try {
			return sqsScanQueueService.hasPendingScan(pr.getApiLabel(), pr.getRepoName(),
					pr.getPrId());
		} catch (RuntimeException e) {
			LOG.warn("Could not check for a pending scan of " + pr.getPRString() + ": " + e);
			return false;
		}
	}

	/**
	 * Builds the key identifying an in-flight scan. Includes the commit hash so that a
	 * force-push to the same Pull Request is treated as new work rather than a duplicate.
	 *
	 * @param pr the pull request being scanned
	 * @return the deduplication key
	 */
	private String buildDedupKey(PullRequest pr) {
		return pr.getApiLabel() + "/" + pr.getRepoName() + "/" + pr.getPrId() + "/"
				+ pr.getCommitHash();
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * This will attempt to recover all PRs not scanned in each repository the system knows about
	 * for every SCM connection. If it detects repositories no longer available, it will disable
	 * them and not check for Pull Requests
	 */
	@Override
	protected void recoverFromDowntime() {
		if (sqsSubmissionEnabled && sqsScanQueueService.isEnabled()) {
			// IMPROVEMENT_PLAN.md item 4.6: PR scans submitted before the restart were
			// published to SQS, not run in-process, so they were never lost - they are
			// still sitting in the queue and SqsScanConsumer (item 4.5) will pick them
			// up as soon as it starts polling. Falling through to the BB-polling
			// recovery below would be redundant (and expensive: it walks every open PR
			// across every repo) work that could itself trigger BB rate limits right at
			// startup - the exact problem this item exists to remove.
			LOG.info(
					"SQS queue handles PR scan recovery automatically; skipping BB-polling downtime recovery.");
			return;
		}

		List<PullRequest> prs = new ArrayList<>();
		Map<String, List<RepositoryEntity>> repoMap = repoService
				.getAllRepos(CodeScanType.PULL_REQUEST);
		for (ApiIntegrationEntity entity : apiService.getAllSettings()) {
			// Only recover if API integration is configured for pull request scans
			if (!entity.getScanType().equals(CodeScanType.PULL_REQUEST)) {
				continue;
			}
			LOG.debug("Recovering using API " + entity.getApiLabel());
			List<PullRequest> recovered = recoverByApi(repoMap, entity);
			prs.addAll(recovered);
		}
		if (!prs.isEmpty()) {
			LOG.info("Need to scan " + prs.size() + " Pull Requests after downtime");
			for (PullRequest pr : prs) {
				try {
					doPullRequestScan(pr);
				} catch (Exception e) {
					LOG.error("Could not submit recovery scan " + pr.getPRString(), e);
				}
			}
		} else {
			LOG.info("No Pull Requests found to recover after downtime");
		}
	}

	private List<PullRequest> recoverByApi(Map<String, List<RepositoryEntity>> repoMap,
			ApiIntegrationEntity entity) {
		List<PullRequest> prs = new ArrayList<>();
		IScmApi api = (IScmApi) entity.createApi();
		List<RepositoryEntity> repos =
				repoMap.getOrDefault(entity.getApiLabel(), new ArrayList<>());
		for (RepositoryEntity repo : repos) {
			// A repository known only from a catalog sync has never had a pull request, so
			// there is nothing to recover; polling it would cost a Bitbucket call per repository
			if (!repo.isEnabled() || !repo.isPrActive()) {
				continue;
			}
			String repoName = repo.getRepoName();
			if (!api.isRepositoryActive(repoName)) {
				LOG.info("Disabling dead repository " + repoName);
				repoService.disableRepository(repo);
			} else {
				LOG.debug("Recovering Repo " + repoName);
				List<PullRequest> recovered = recoverByRepo(entity, api, repo);
				prs.addAll(recovered);
			}
		}
		return prs;
	}

	private List<PullRequest> recoverByRepo(ApiIntegrationEntity entity, IScmApi api,
			RepositoryEntity repo) {
		long repoLastReview = repo.getLastReviewedDate();
		List<PullRequest> prUpdates = api.getOpenPullRequestsForRepository(repo.getRepoName())
				.stream().filter(pr -> {
					LOG.debug("Working on pr: " + pr.getPrId());
					try {
						PullRequestContainerEntity prEntity =
								prScanResultService.getPullRequestByLabelRepoAndId(
										entity.getApiLabel(), repo.getRepoName(), pr.getPrId());

						// This is an ancient pr and older than our last check on the repository.
						if (repoLastReview > pr.getUpdateTime()) {
							return false;
						}
						// if we haven't seen this PR add it
						if (prEntity == null) {
							return true;
						}
						// if we have seen it, but reviewed it before its last update, add it
						if (prEntity.getLastReviewedDate() < pr.getUpdateTime()) {
							return true;
						}
					} catch (Exception e) {
						LOG.error("Exception while trying to recover " + pr.getPRString(), e);
					}
					// otherwise we've seen it and reviewed it after the last update, so skip
					return false;
				}).collect(Collectors.toList());

		LOG.debug("Found " + prUpdates.size() + " prs since "
				+ repo.getLastReviewedDateAsDate());

		return prUpdates;
	}
}
