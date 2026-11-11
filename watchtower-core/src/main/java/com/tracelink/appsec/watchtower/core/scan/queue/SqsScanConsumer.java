package com.tracelink.appsec.watchtower.core.scan.queue;

import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.watchtower.core.exception.PullRequestNotFoundException;
import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.RepositorySlug;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.ScanExecutionResult;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanningService;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryService;

import software.amazon.awssdk.services.sqs.model.Message;

/**
 * Polls the SQS scan queue (IMPROVEMENT_PLAN.md item 4.5) and feeds
 * {@link PRScanningService}'s existing thread pool - SQS is a durable front-end, not a
 * replacement execution engine. A no-op unless both
 * {@code watchtower.queue.sqs.submission-enabled} is true and an
 * {@linkplain SqsScanQueueService} queue URL is configured, matching item 4.4's
 * publish-side gate exactly: nothing changes for a deployment that hasn't opted in.
 * <p>
 * {@link ScanRequestMessage} carries only {@code apiLabel}/{@code repoName}/{@code prId}
 * (plus {@code commitHash}/{@code enqueuedAt}, used only for logging/dedup, not
 * lookups), so this class re-runs the same ruleset/scanner/api-lookup/resolved-state
 * validation {@code PRScanningService.doPullRequestScan()} does before calling
 * {@linkplain PRScanningService#executeScan(PullRequest, IScmApi, RulesetEntity)}
 * directly - never {@code doPullRequestScan()} itself, which would re-publish to SQS
 * and loop. Re-fetching and re-checking state here is intentional, not wasted work: a
 * PR can change between enqueue and dequeue (get merged, lose its ruleset, etc.), and
 * this is where that is caught.
 *
 * @author Watchtower
 */
@Component
public class SqsScanConsumer {
	private static final Logger LOG = LoggerFactory.getLogger(SqsScanConsumer.class);

	private final SqsScanQueueService sqsScanQueueService;
	private final PRScanningService prScanningService;
	private final PRScanResultService prScanResultService;
	private final ApiIntegrationService apiService;
	private final RepositoryService repoService;
	private final ScanRegistrationService scanRegistrationService;
	private final boolean sqsSubmissionEnabled;
	private final int maxThreads;
	private final ObjectMapper objectMapper;
	private final int visibilityExtensionSeconds;
	private final ScheduledExecutorService visibilityHeartbeat;
	/** Set by the first poll, which logs that queued scans are being picked up. */
	private volatile boolean polling;

	@Autowired
	public SqsScanConsumer(SqsScanQueueService sqsScanQueueService,
			PRScanningService prScanningService, PRScanResultService prScanResultService,
			ApiIntegrationService apiService, RepositoryService repoService,
			ScanRegistrationService scanRegistrationService,
			@Value("${watchtower.queue.sqs.submission-enabled:false}") boolean sqsSubmissionEnabled,
			@Value("${watchtower.threads.prscan:4}") int maxThreads,
			@Value("${watchtower.queue.sqs.visibility-extension-seconds:300}")
			int visibilityExtensionSeconds) {
		this.sqsScanQueueService = sqsScanQueueService;
		this.prScanningService = prScanningService;
		this.prScanResultService = prScanResultService;
		this.apiService = apiService;
		this.repoService = repoService;
		this.scanRegistrationService = scanRegistrationService;
		this.sqsSubmissionEnabled = sqsSubmissionEnabled;
		this.maxThreads = maxThreads;
		this.visibilityExtensionSeconds = visibilityExtensionSeconds;
		this.visibilityHeartbeat = Executors.newSingleThreadScheduledExecutor(runnable -> {
			Thread thread = new Thread(runnable, "sqs-visibility-heartbeat");
			thread.setDaemon(true);
			return thread;
		});
		// A plain ObjectMapper for the same reason SqsScanQueueService constructs its
		// own: ScanRequestMessage needs no custom Jackson configuration, so there is
		// nothing to gain from depending on a Spring-managed instance.
		this.objectMapper = new ObjectMapper();
	}

	SqsScanConsumer(SqsScanQueueService sqsScanQueueService,
			PRScanningService prScanningService, PRScanResultService prScanResultService,
			ApiIntegrationService apiService, RepositoryService repoService,
			ScanRegistrationService scanRegistrationService, boolean sqsSubmissionEnabled,
			int maxThreads) {
		this(sqsScanQueueService, prScanningService, prScanResultService, apiService, repoService,
				scanRegistrationService, sqsSubmissionEnabled, maxThreads, 300);
	}

	/**
	 * Polls SQS for scan requests and feeds them to
	 * {@linkplain PRScanningService#executeScan(PullRequest, IScmApi, RulesetEntity)}.
	 * A no-op when SQS submission isn't enabled and configured, when the system is
	 * quiesced or paused, or when the thread pool is already at capacity - polling
	 * again in each of those cases would just requeue messages we can't act on yet.
	 */
	@Scheduled(fixedDelayString = "${watchtower.queue.sqs.consumer-poll-delay-ms:1000}")
	public void poll() {
		if (!sqsSubmissionEnabled || !sqsScanQueueService.isEnabled()) {
			return;
		}
		if (!polling) {
			// Scheduled tasks start only once startup has finished, so a scan queued during
			// startup waits until this line.
			polling = true;
			LOG.info("Polling the SQS scan queue for pull request scans");
		}
		if (prScanningService.isQuiesced() || prScanningService.isPaused()) {
			return;
		}
		if (prScanningService.getTaskNumActive() >= maxThreads) {
			return;
		}

		List<Message> messages = sqsScanQueueService.poll();
		for (Message message : messages) {
			processMessage(message);
		}
	}

	private void processMessage(Message message) {
		ScanRequestMessage request;
		try {
			request = objectMapper.readValue(message.body(), ScanRequestMessage.class);
		} catch (JsonProcessingException e) {
			LOG.error("Failed to deserialize SQS scan request; deleting unreadable message", e);
			sqsScanQueueService.delete(message.receiptHandle());
			return;
		}

		boolean stillInFlight;
		try {
			stillInFlight = executeFromMessage(request, message.receiptHandle());
		} catch (PullRequestNotFoundException e) {
			// The provider answered that there is no such pull request. Redelivery would ask
			// again every visibility timeout until the dead-letter queue, with the repository's
			// scans waiting behind it, and the answer cannot change.
			LOG.info("Dropping SQS scan request for " + request.apiLabel() + "/"
					+ request.repoName() + "/" + request.prId() + ": pull request not found");
			sqsScanQueueService.markValidationFailed(request, "Pull request not found");
			sqsScanQueueService.delete(message.receiptHandle());
			return;
		} catch (Exception e) {
			sqsScanQueueService.markQueued(request);
			// Left in SQS deliberately: the visibility timeout will redeliver it, rather
			// than losing the request to a transient failure (e.g. Bitbucket briefly
			// unreachable).
			LOG.error("Failed to execute scan from SQS for " + request.apiLabel() + "/"
					+ request.repoName() + "/" + request.prId(), e);
			return;
		}
		if (!stillInFlight) {
			// Either nothing was ever submitted (deduplicated - another execution owns
			// the outcome; or a permanent condition like a missing ruleset, which
			// redelivery could never fix) or the scan already ran synchronously to a
			// terminal, non-error state (already-resolved). Either way there is nothing
			// left to wait on.
			sqsScanQueueService.delete(message.receiptHandle());
		}
		// Otherwise, deletion is deferred to the whenComplete() callback registered
		// inside executeFromMessage() - deleting here, before the agent submitted to
		// PRScanningService's executor has actually run, would delete the message
		// before knowing whether the scan it names ever succeeded.
	}

	/**
	 * @param request       the deserialized scan request
	 * @param receiptHandle the SQS receipt handle for the message carrying it
	 * @return true if a scan agent is now running asynchronously and this method has
	 *         already arranged for the message to be deleted once it finishes (see
	 *         {@code AbstractScanAgent#hasFailed()}); false if there is nothing
	 *         further to wait on and the caller should delete the message immediately
	 */
	private boolean executeFromMessage(ScanRequestMessage request, String receiptHandle)
			throws ScanRejectedException {
		LOG.info("Picked up the queued scan of PR " + request.apiLabel() + "/"
				+ request.repoName() + "/" + request.prId());
		ApiIntegrationEntity apiEntity = apiService.findByLabel(request.apiLabel());
		if (apiEntity == null) {
			LOG.info("Dropping SQS scan request for " + request.repoName() + "/" + request.prId()
					+ ": integration " + request.apiLabel() + " is no longer configured");
			sqsScanQueueService.markValidationFailed(request,
					"Connection is no longer configured");
			return false;
		}

		// The slug, as doPullRequestScan names it, also for a message queued before it did; the
		// message itself keeps its name, which the queue's bookkeeping is keyed on
		String repoName = RepositorySlug.of(request.repoName());
		RepositoryEntity repo = repoService.upsertRepo(CodeScanType.PULL_REQUEST,
				request.apiLabel(), repoName);
		if (repo.isScanningPaused()) {
			LOG.info("Skipping SQS scan request for " + request.repoName() + "/"
					+ request.prId() + ": scanning of the repository is paused");
			sqsScanQueueService.markCompleted(request);
			return false;
		}
		RulesetEntity ruleset = repo.getRuleset();
		if (ruleset == null) {
			LOG.info("Dropping SQS scan request for " + request.repoName() + "/" + request.prId()
					+ ": repository is no longer configured with a ruleset");
			sqsScanQueueService.markValidationFailed(request,
					"Repository has no configured ruleset");
			return false;
		}
		if (!scanRegistrationService.hasCodeScanners()) {
			LOG.info("Dropping SQS scan request for " + request.repoName() + "/" + request.prId()
					+ ": no scanners are configured");
			sqsScanQueueService.markValidationFailed(request,
					"No code scanners are configured");
			return false;
		}

		IScmApi api = (IScmApi) apiEntity.createApi();
		PullRequest pr = new PullRequest(request.apiLabel());
		pr.setRepoName(repoName);
		pr.setPrId(request.prId());
		pr = api.updatePRData(pr);

		if (pr.getState() != null && pr.getState().isResolved()) {
			LOG.info("SQS scan request for " + pr.getPRString() + " is already " + pr.getState()
					+ "; resolving without scanning");
			// This request was queued and is being dropped: a scan was pending at the merge.
			prScanResultService.markPrResolved(pr, true);
			sqsScanQueueService.markCompleted(request);
			return false;
		}

		sqsScanQueueService.markRunning(request);
		ScanExecutionResult executionResult =
				prScanningService.executeScan(pr, api, ruleset, receiptHandle,
						request.enqueuedAt());
		if (executionResult.future() == null) {
			// DEDUPLICATED: an identical scan is already running (e.g. submitted by a
			// webhook that raced this message) - that other execution owns the
			// eventual success/failure, so this message has nothing left to wait on.
			return false;
		}
		if (!sqsScanQueueService.requeue(receiptHandle, visibilityExtensionSeconds)) {
			LOG.warn("Could not extend initial SQS visibility timeout for an active scan");
		}
		long heartbeatSeconds = Math.max(1, visibilityExtensionSeconds / 2L);
		ScheduledFuture<?> heartbeat = visibilityHeartbeat.scheduleAtFixedRate(
				() -> sqsScanQueueService.requeue(receiptHandle, visibilityExtensionSeconds),
				heartbeatSeconds, heartbeatSeconds, TimeUnit.SECONDS);
		executionResult.future().whenComplete((result, error) -> {
			heartbeat.cancel(false);
			if (!executionResult.agent().hasFailed()) {
				sqsScanQueueService.delete(receiptHandle);
				sqsScanQueueService.markCompleted(request);
			} else {
				sqsScanQueueService.markQueued(request);
			}
			// On failure, leave the message in SQS for its visibility timeout to
			// redeliver it - unless handleScanException() already re-enqueued it
			// itself with an explicit delay (IMPROVEMENT_PLAN.md item 4.7's rate-limit
			// handling), which changed that timeout already.
		});
		return true;
	}

	@PreDestroy
	void shutdownVisibilityHeartbeat() {
		visibilityHeartbeat.shutdownNow();
	}
}
