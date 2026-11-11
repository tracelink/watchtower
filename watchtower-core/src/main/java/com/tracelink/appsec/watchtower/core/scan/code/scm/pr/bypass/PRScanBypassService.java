package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;

import java.time.Clock;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.alerting.AlertEvent;
import com.tracelink.appsec.watchtower.core.alerting.AlertItem;
import com.tracelink.appsec.watchtower.core.alerting.AlertService;
import com.tracelink.appsec.watchtower.core.alerting.AlertTypeRegistry;
import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanEntity;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRCommentFormat;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanSubmitResult;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanningService;
import com.tracelink.appsec.watchtower.core.verification.ILiveVerifier;
import com.tracelink.appsec.watchtower.core.verification.LiveVerificationStatus;

import io.micrometer.core.instrument.MeterRegistry;

/**
 * Lets a privileged user stop Watchtower blocking one pull request, for the findings of its
 * latest scan, and revoke that again (§4.12 of the secrets-engine plan). Scans ask
 * {@link #activeFor} which findings no longer block.
 * <p>
 * The bypass is saved before the SCM is told; an SCM failure is reported to the caller but
 * never undoes it, so the next scan still honours it.
 *
 * @author Watchtower
 */
@Service
public class PRScanBypassService {
 @Autowired(required=false) private com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService remoteAssessments;
 @Autowired(required=false) private BypassIdentityWriter identityWriter;

	/** A pull request's blocking was bypassed. */
	public static final String PR_BYPASSED = "PR_BYPASSED";

	/** Counter of bypass actions, tagged {@code action} (bypass, revoke, request, …). */
	public static final String METRIC = "watchtower.pr.bypass";

	private static final Logger LOG = LoggerFactory.getLogger(PRScanBypassService.class);

	private final PullRequestBypassRepository bypassRepository;
	private final PRScanRepository scanRepository;
	private final ApiIntegrationService apiService;
	private final AlertService alertService;
	private final ObjectProvider<ILiveVerifier> verifiers;
	/** A provider, not the bean: the scanning service also depends on this one. */
	private final ObjectProvider<PRScanningService> scanningService;
	private final MeterRegistry meterRegistry;
	private final String publicUrl;
	private final Clock clock;

	@Autowired
	public PRScanBypassService(PullRequestBypassRepository bypassRepository,
			PRScanRepository scanRepository, ApiIntegrationService apiService,
			AlertService alertService, AlertTypeRegistry registry,
			ObjectProvider<ILiveVerifier> verifiers,
			ObjectProvider<PRScanningService> scanningService, MeterRegistry meterRegistry,
			@Value("${watchtower.publicUrl:#{null}}") String publicUrl) {
		this(bypassRepository, scanRepository, apiService, alertService, registry, verifiers,
				scanningService, meterRegistry, publicUrl, Clock.systemUTC());
	}

	PRScanBypassService(PullRequestBypassRepository bypassRepository,
			PRScanRepository scanRepository, ApiIntegrationService apiService,
			AlertService alertService, AlertTypeRegistry registry,
			ObjectProvider<ILiveVerifier> verifiers,
			ObjectProvider<PRScanningService> scanningService, MeterRegistry meterRegistry,
			String publicUrl, Clock clock) {
		this.meterRegistry = meterRegistry;
		this.bypassRepository = bypassRepository;
		this.scanRepository = scanRepository;
		this.apiService = apiService;
		this.alertService = alertService;
		this.verifiers = verifiers;
		this.scanningService = scanningService;
		this.publicUrl = publicUrl;
		this.clock = clock;
		registry.register(PR_BYPASSED, "Someone bypassed Watchtower's blocking of a pull"
				+ " request.", false);
	}

	/**
	 * Stops the scan's findings blocking its pull request, approves it (when the integration
	 * manages review state) and comments on it.
	 *
	 * @param scanId the pull request's latest scan
	 * @param user   who is bypassing
	 * @param reason why; required
	 * @return true if the SCM was updated; false if the bypass is saved but the SCM was not
	 * @throws PRScanBypassException if the bypass is refused; the message is safe to show
	 */
	public boolean bypass(long scanId, String user, String reason) {
  return bypass(scanId,user,reason,BypassReasonCode.OTHER);
 }
 public boolean bypass(long scanId,String user,String reason,BypassReasonCode reasonCode) {
		String validReason = validReason(reason);
		PullRequestScanEntity scan = findScan(scanId);
		String refusal = refusalFor(scan);
		if (refusal != null) {
			throw new PRScanBypassException(refusal);
		}
		PullRequestBypassEntity bypass = bypassRepository.save(newBypass(scan, user, validReason, reasonCode));
		if(identityWriter!=null)identityWriter.record(bypass.getId(),scan);
  count("bypass");
		PullRequestContainerEntity container = scan.getContainer();
		LOG.info("Blocking of pull request {}/{} #{} bypassed by {} (bypass {}, scan {})",
				container.getApiLabel(), container.getRepoName(), container.getPrId(), user,
				bypass.getId(), scanId);

		PullRequest pr = pullRequest(scan);
		if (scan.getRemoteAssessmentState() != null) {
			// A local-only bypass cannot approve a selected provider's pending or stale result.
			// A new aggregate execution applies both local and provider bypass coverage.
			queueRescan(container); raiseBypassed(scan, bypass); return false;
		}
		String comment = bypassNote(user, validReason) + " New blocking findings still block.";
		boolean scmUpdated = updateScm(pr, api -> api.approvePR(pr) & api.sendComment(pr, comment));
		raiseBypassed(scan, bypass);
		return scmUpdated;
	}

	/**
	 * Ends every active bypass of the scan's pull request, comments, and queues a rescan so the
	 * pull request is blocked again straight away.
	 *
	 * @param scanId a scan of the pull request
	 * @param user   who is revoking
	 * @return true if the rescan was queued; false if blocking resumes only on the next push
	 * @throws PRScanBypassException if there is nothing to revoke; the message is safe to show
	 */
	public boolean revoke(long scanId, String user) {
		PullRequestContainerEntity container = findScan(scanId).getContainer();
		List<PullRequestBypassEntity> active = bypassRepository.findActive(
				container.getApiLabel(), container.getRepoName(), container.getPrId());
		if (active.isEmpty()) {
			throw new PRScanBypassException("No active bypass on this pull request.");
		}
		long now = clock.millis();
		active.forEach(bypass -> bypass.revoke(user, now));
		bypassRepository.saveAll(active);
		count("revoke");
		LOG.info("Blocking bypass of pull request {}/{} #{} revoked by {} ({} bypasses)",
				container.getApiLabel(), container.getRepoName(), container.getPrId(), user,
				active.size());

		boolean rescanQueued = queueRescan(container);
		PullRequest pr = container.toPullRequest();
		String comment = "Blocking bypass revoked by " + PRCommentFormat.escape(user) + ". "
				+ (rescanQueued
				? "Watchtower is rescanning; blocking findings block again."
				: "Blocking findings block again from the next push.");
		updateScm(pr, api -> api.sendComment(pr, comment));
		return rescanQueued;
	}

	/**
	 * Never throws: a failed lookup means nothing is bypassed, so the scan blocks as usual.
	 *
	 * @param apiLabel the SCM integration
	 * @param repoName the repository
	 * @param prId     the pull request
	 * @return what the pull request's active bypasses cover, if it has any
	 */
	public Optional<ActiveBypass> activeFor(String apiLabel, String repoName, String prId) {
		try {
			return toActive(bypassRepository.findActive(apiLabel, repoName, prId));
		} catch (RuntimeException e) {
			LOG.error("Could not read bypasses of pull request {}/{} #{}; blocking as usual",
					apiLabel, repoName, prId, e);
			return Optional.empty();
		}
	}

	/**
	 * @param scanId     a pull request scan
	 * @param forManager whether the viewer may bypass. Only they see why bypassing is refused,
	 *                   so for others the refusal (and its live-verification lookup over every
	 *                   scan of the PR) is skipped.
	 * @return what its report shows about bypassing
	 */
	public BypassState stateFor(long scanId, boolean forManager) {
		PullRequestScanEntity scan = scanRepository.findById(scanId);
		if (scan == null) {
			return BypassState.NONE;
		}
		PullRequestContainerEntity container = scan.getContainer();
		ActiveBypass active = activeFor(container.getApiLabel(), container.getRepoName(),
				container.getPrId()).orElse(null);
		// A bypass made after the scan leaves the scan's own flag set until the next scan. The
		// report must not show "Blocking" next to "Bypassed" for a change that no longer blocks.
		boolean blocked = scan.isBlocked() && !bypassCoversEverythingBlocking(scan, active);
		String refusal = blocked && forManager ? refusalFor(scan) : null;
		return new BypassState(blocked, refusal, active);
	}

	/**
	 * @return true if the scan's blocking is entirely from findings the active bypass covers. A
	 *         scan with a remote review (AWS) can also block through it, which a bypass of local
	 *         findings does not cover, so its own flag stands.
	 */
	private static boolean bypassCoversEverythingBlocking(PullRequestScanEntity scan,
			ActiveBypass active) {
		if (active == null || scan.getRemoteAssessmentState() != null) {
			return false;
		}
		List<PullRequestViolationEntity> blocking = scan.getViolations().stream()
				.filter(v -> v.isBlocking() && v.isNewViolation()).toList();
		return !blocking.isEmpty() && blocking.stream()
				.allMatch(v -> active.covers(v.getViolationName(), v.getFileName()));
	}

	/**
	 * @param action what happened, e.g. {@code bypass}; no repository tag (cardinality) - the
	 *               audit page has per-repository numbers
	 */
	void count(String action) {
		meterRegistry.counter(METRIC, "action", action).increment();
	}

	static String validReason(String reason) {
		String trimmed = StringUtils.trimToEmpty(reason);
		if (trimmed.isEmpty()) {
			throw new PRScanBypassException("A reason is required to bypass blocking.");
		}
		if (trimmed.length() > PullRequestBypassEntity.MAX_REASON_LENGTH) {
			throw new PRScanBypassException("The reason must be at most "
					+ PullRequestBypassEntity.MAX_REASON_LENGTH + " characters.");
		}
		return trimmed;
	}

	PullRequestScanEntity findScan(long scanId) {
		PullRequestScanEntity scan = scanRepository.findById(scanId);
		if (scan == null) {
			throw new PRScanBypassException("Unknown scan.");
		}
		return scan;
	}

	/**
	 * @return why the scan cannot be bypassed now, or null if it can
	 */
	String refusalFor(PullRequestScanEntity scan) {
		PullRequestContainerEntity container = scan.getContainer();
		if (!scan.isBlocked()) {
			return "This scan is not blocking its pull request.";
		}
		if (latestScanId(container) != scan.getId()) {
			return "Only the latest scan of a pull request can be bypassed.";
		}
		if (container.isResolved()) {
			return "The pull request is closed (merged or declined).";
		}
		return liveRefusal(container);
	}

	static long latestScanId(PullRequestContainerEntity container) {
		return container.getScans().stream().mapToLong(AbstractScanEntity::getId).max()
				.orElse(-1);
	}

	/**
	 * Fails closed: if the statuses cannot be read, the bypass is refused.
	 */
	private String liveRefusal(PullRequestContainerEntity container) {
		ILiveVerifier verifier = verifiers.getIfUnique();
		if (verifier == null) {
			return null;
		}
		Set<Long> violationIds = container.getScans().stream()
				.flatMap(scan -> scan.getViolations().stream())
				.map(AbstractScanViolationEntity::getId)
				.collect(Collectors.toUnmodifiableSet());
		if (violationIds.isEmpty()) {
			return null;
		}
		try {
			Collection<LiveVerificationStatus> statuses =
					verifier.getStatuses(violationIds).values();
			return statuses.contains(LiveVerificationStatus.LIVE)
					? "A secret on this pull request is verified live. Rotate it first;"
							+ " bypassing is disabled while any finding is live."
					: null;
		} catch (RuntimeException e) {
			LOG.warn("Could not read live verification statuses of pull request {}",
					container.getPrId(), e);
			return "Could not check live verification status. Try again later.";
		}
	}

	private PullRequestBypassEntity newBypass(PullRequestScanEntity scan, String user,
			String reason, BypassReasonCode reasonCode) {
		PullRequestContainerEntity container = scan.getContainer();
		PullRequestBypassEntity bypass = new PullRequestBypassEntity();
		bypass.setApiLabel(container.getApiLabel());
		bypass.setRepoName(container.getRepoName());
		bypass.setPrId(container.getPrId());
		bypass.setScanId(scan.getId());
		bypass.setCommitHash(scan.getCommitHash());
		bypass.setBypassedBy(user);
		bypass.setReason(reason);
  bypass.setReasonCode(reasonCode);
		bypass.setCreatedAt(clock.millis());
		// Every finding, not only the blocking ones: those never blocked, so covering them is
		// harmless, and the scan does not keep which ones blocked.
		Set<BypassedFinding> covered = scan.getViolations().stream()
				.map(v -> new BypassedFinding(v.getViolationName(), v.getFileName()))
				.collect(Collectors.toSet());
		if (scan.getRemoteAssessmentState() != null && remoteAssessments != null)
			covered.addAll(remoteAssessments.bypassFindings(scan.getId()));
		bypass.setFindings(covered);
		return bypass;
	}

	private static PullRequest pullRequest(PullRequestScanEntity scan) {
		PullRequest pr = scan.getContainer().toPullRequest();
		// Approving checks this is still the head commit, so a push since is never approved.
		pr.setCommitHash(scan.getCommitHash());
		return pr;
	}

	/**
	 * @return false if the integration is gone, a call reported failure, or a call threw
	 */
	/**
	 * Tells the pull request, in a comment, that a bypass request made there was declined, so the
	 * person who asked does not have to open Watchtower to find out. A failed comment is logged.
	 *
	 * @param scanId  a scan of the pull request
	 * @param decider who declined
	 * @param note    why, or null
	 */
	public void commentDeclined(long scanId, String decider, String note) {
		PullRequest pr = findScan(scanId).getContainer().toPullRequest();
		String comment = "Bypass request declined by " + PRCommentFormat.escape(decider)
				+ (note == null ? "." : ": " + PRCommentFormat.quote(note) + ".");
		updateScm(pr, api -> api.sendComment(pr, comment));
	}

	private boolean updateScm(PullRequest pr, Predicate<IScmApi> calls) {
		ApiIntegrationEntity integration = apiService.findByLabel(pr.getApiLabel());
		if (integration == null) {
			LOG.warn("Cannot update pull request {}: integration {} is gone", pr.getPRString(),
					pr.getApiLabel());
			return false;
		}
		try {
			return calls.test((IScmApi) integration.createApi());
		} catch (RuntimeException e) {
			LOG.warn("Could not update pull request {} after a bypass change", pr.getPRString(),
					e);
			return false;
		}
	}

	private boolean queueRescan(PullRequestContainerEntity container) {
		PRScanningService scanner = scanningService.getIfAvailable();
		if (scanner == null) {
			return false;
		}
		// No commit hash: the scan fetches the current head, and SQS does not deduplicate it
		// against the scan that was bypassed.
		PullRequest pr = container.toPullRequest();
		try {
			PRScanSubmitResult result = scanner.doPullRequestScan(pr);
			return result == PRScanSubmitResult.QUEUED
					|| result == PRScanSubmitResult.DEDUPLICATED;
		} catch (ScanRejectedException | RuntimeException e) {
			LOG.warn("Could not queue a rescan of pull request {} after revoking its bypass",
					pr.getPRString(), e);
			return false;
		}
	}

	private void raiseBypassed(PullRequestScanEntity scan, PullRequestBypassEntity bypass) {
		PullRequestContainerEntity container = scan.getContainer();
		String link = reportLink(publicUrl, scan.getId());
		AlertItem item = new AlertItem("bypass\u0000" + bypass.getId() + "\u0000"
				+ bypass.getCreatedAt(), null, "By " + bypass.getBypassedBy() + ": "
						+ sentence(bypass.getReason()) + " Covers "
						+ bypass.getFindings().size() + " finding(s).");
		try {
			alertService.raise(new AlertEvent(PR_BYPASSED, container.getApiLabel(),
					container.getRepoName(), "Blocking bypassed on pull request #"
							+ container.getPrId(),
					link, String.join("\u0000", "bypass", container.getApiLabel(),
							container.getRepoName(), container.getPrId()),
					List.of(item)));
		} catch (RuntimeException e) {
			LOG.warn("Could not raise the bypass alert for scan {}", scan.getId(), e);
		}
	}

	private static Optional<ActiveBypass> toActive(List<PullRequestBypassEntity> active) {
		Optional<PullRequestBypassEntity> newest = active.stream()
				.max(Comparator.comparingLong(PullRequestBypassEntity::getCreatedAt));
		if (newest.isEmpty()) {
			return Optional.empty();
		}
		Set<BypassedFinding> findings = new HashSet<>();
		active.forEach(bypass -> findings.addAll(bypass.getFindings()));
		return Optional.of(new ActiveBypass(newest.get().getBypassedBy(),
				newest.get().getReason(), newest.get().getCreatedAt(), findings));
	}

	/**
	 * @param publicUrl Watchtower's external base URL, may be blank
	 * @param scanId    a pull request scan
	 * @return the scan's report URL for alerts, or null without a public URL
	 */
	static String reportLink(String publicUrl, long scanId) {
		return StringUtils.isBlank(publicUrl) ? null
				: StringUtils.removeEnd(publicUrl.trim(), "/") + "/scan/report/" + scanId;
	}

	/**
	 * @param user   who bypassed
	 * @param reason why
	 * @return the sentence PR comments use to name a bypass
	 */
	public static String bypassNote(String user, String reason) {
		return "Blocking bypassed by " + PRCommentFormat.escape(user) + ": "
				+ PRCommentFormat.quote(reason) + ".";
	}

	/**
	 * For alert text only (internal Chat channels). PR comments use
	 * {@link PRCommentFormat#quote}, which also stops links and formatting.
	 *
	 * @return the reason on one line, ending in a full stop
	 */
	public static String sentence(String reason) {
		String oneLine = StringUtils.normalizeSpace(reason);
		return StringUtils.endsWithAny(oneLine, ".", "!", "?") ? oneLine : oneLine + ".";
	}
}
