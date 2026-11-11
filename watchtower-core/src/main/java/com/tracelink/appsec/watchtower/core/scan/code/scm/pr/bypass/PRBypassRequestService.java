package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;

import java.time.Clock;
import java.util.List;
import java.util.Optional;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.alerting.AlertEvent;
import com.tracelink.appsec.watchtower.core.alerting.AlertItem;
import com.tracelink.appsec.watchtower.core.alerting.AlertService;
import com.tracelink.appsec.watchtower.core.alerting.AlertTypeRegistry;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;

/**
 * Bypass requests (§4.17): anyone who can see a blocked pull request's report can ask for a
 * bypass, with a reason; someone else with the bypass privilege approves (a normal bypass, under
 * their name) or declines it. The same refusals as a bypass apply. A newer scan of the PR
 * supersedes a pending request, noticed the next time it is looked up.
 *
 * @author Watchtower
 */
@Service
public class PRBypassRequestService {

	/** Someone asked for a pull request's blocking to be bypassed. */
	public static final String PR_BYPASS_REQUESTED = "PR_BYPASS_REQUESTED";

	private static final Logger LOG = LoggerFactory.getLogger(PRBypassRequestService.class);

	private final PullRequestBypassRequestRepository requestRepository;
	private final PRScanBypassService bypassService;
	private final AlertService alertService;
	private final String publicUrl;
	private final Clock clock;

	@Autowired
	public PRBypassRequestService(PullRequestBypassRequestRepository requestRepository,
			PRScanBypassService bypassService, AlertService alertService,
			AlertTypeRegistry registry, @Value("${watchtower.publicUrl:#{null}}") String publicUrl) {
		this(requestRepository, bypassService, alertService, registry, publicUrl,
				Clock.systemUTC());
	}

	PRBypassRequestService(PullRequestBypassRequestRepository requestRepository,
			PRScanBypassService bypassService, AlertService alertService,
			AlertTypeRegistry registry, String publicUrl, Clock clock) {
		this.requestRepository = requestRepository;
		this.bypassService = bypassService;
		this.alertService = alertService;
		this.publicUrl = publicUrl;
		this.clock = clock;
		registry.register(PR_BYPASS_REQUESTED, "Someone asked for Watchtower's blocking of a pull"
				+ " request to be bypassed.", false);
	}

	/**
	 * @param scanId the pull request's latest, blocked scan
	 * @param user   who asks
	 * @param reason why; required
	 * @return the saved request
	 * @throws PRScanBypassException if refused; the message is safe to show
	 */
	public PullRequestBypassRequestEntity request(long scanId, String user, String reason) {
		return request(scanId, user, reason, RequestSource.WATCHTOWER, null);
	}

	/**
	 * @param scanId    the pull request's latest, blocked scan
	 * @param user      who asks: a Watchtower login, or an SCM display name for a PR comment
	 * @param reason    why; required
	 * @param source    where the request was made
	 * @param scmUserId for {@link RequestSource#PR_COMMENT}, the commenter's SCM account id
	 * @return the saved request
	 * @throws PRScanBypassException if refused; the message is safe to show
	 */
	public PullRequestBypassRequestEntity request(long scanId, String user, String reason,
   RequestSource source, String scmUserId) { return request(scanId,user,reason,source,scmUserId,BypassReasonCode.OTHER); }
 public PullRequestBypassRequestEntity request(long scanId,String user,String reason,BypassReasonCode code) {
  return request(scanId,user,reason,RequestSource.WATCHTOWER,null,code);
 }
 public PullRequestBypassRequestEntity request(long scanId,String user,String reason,RequestSource source,String scmUserId,BypassReasonCode code) {
		String validReason = PRScanBypassService.validReason(reason);
		PullRequestScanEntity scan = bypassService.findScan(scanId);
		String refusal = bypassService.refusalFor(scan);
		if (refusal != null) {
			throw new PRScanBypassException(refusal);
		}
		if (pending(scan.getContainer()).isPresent()) {
			throw new PRScanBypassException(
					"A bypass request is already pending for this pull request.");
		}
		PullRequestBypassRequestEntity request;
		try {
			PullRequestBypassRequestEntity unsaved = newRequest(scan, user, validReason);
			unsaved.setSource(source);
   unsaved.setReasonCode(code);
			unsaved.setRequesterScmId(StringUtils.abbreviate(scmUserId, 64));
			request = requestRepository.save(unsaved);
		} catch (DataIntegrityViolationException e) {
			// Another request for this pull request was saved since the check above.
			throw new PRScanBypassException(
					"A bypass request is already pending for this pull request.");
		}
		bypassService.count("request");
		PullRequestContainerEntity container = scan.getContainer();
		LOG.info("Bypass of pull request {}/{} #{} requested by {} via {} (request {}, scan {})",
				container.getApiLabel(), container.getRepoName(), container.getPrId(), user,
				source, request.getId(), scanId);
		raiseRequested(scan, request);
		return request;
	}

	/**
	 * Bypasses the pull request as the approver, with the requester's reason.
	 *
	 * @param scanId a scan of the pull request
	 * @param user   the approver; never the requester
	 * @return true if the SCM was updated (see {@link PRScanBypassService#bypass})
	 * @throws PRScanBypassException if refused; the request then stays pending
	 */
	public boolean approve(long scanId, String user) {
		PullRequestBypassRequestEntity request = pendingFor(scanId);
		if (StringUtils.equalsIgnoreCase(user, request.getRequestedBy())) {
			throw new PRScanBypassException("You can't approve your own request.");
		}
		long now = clock.millis();
		// Claimed before bypassing, so a second approver at the same moment is refused.
		claim(request, BypassRequestStatus.APPROVED, user, now, null);
		boolean scmUpdated;
		try {
			scmUpdated = request.getReasonCode()==null || request.getReasonCode()==BypassReasonCode.OTHER
     ? bypassService.bypass(request.getScanId(), user, approvedReason(request))
     : bypassService.bypass(request.getScanId(), user, approvedReason(request),request.getReasonCode());
		} catch (PRScanBypassException e) {
			requestRepository.reopen(request.getId(), pendingKeyOf(request),
					BypassRequestStatus.APPROVED, BypassRequestStatus.PENDING);
			throw e;
		}
		request.decide(BypassRequestStatus.APPROVED, user, now, null);
		bypassService.count("approve");
		LOG.info("Bypass request {} approved by {}", request.getId(), user);
		return scmUpdated;
	}

	/**
	 * @param scanId a scan of the pull request
	 * @param user   the decider; not the requester, who withdraws instead
	 * @param note   optional, at most 1000 characters
	 * @throws PRScanBypassException if refused
	 */
	public void decline(long scanId, String user, String note) {
		PullRequestBypassRequestEntity request = pendingFor(scanId);
		if (StringUtils.equalsIgnoreCase(user, request.getRequestedBy())) {
			throw new PRScanBypassException("Withdraw your own request instead.");
		}
		String validNote = StringUtils.trimToNull(note);
		if (validNote != null && validNote.length() > PullRequestBypassEntity.MAX_REASON_LENGTH) {
			throw new PRScanBypassException("The note must be at most "
					+ PullRequestBypassEntity.MAX_REASON_LENGTH + " characters.");
		}
		long now = clock.millis();
		claim(request, BypassRequestStatus.DECLINED, user, now, validNote);
		request.decide(BypassRequestStatus.DECLINED, user, now, validNote);
		bypassService.count("decline");
		if (request.isFromPullRequestComment()) {
			bypassService.commentDeclined(scanId, user, validNote);
		}
		LOG.info("Bypass request {} declined by {}", request.getId(), user);
	}

	/**
	 * @param scanId a scan of the pull request
	 * @param user   the requester
	 * @throws PRScanBypassException if there is no pending request or it is someone else's
	 */
	public void withdraw(long scanId, String user) {
		PullRequestBypassRequestEntity request = pendingFor(scanId);
		if (!StringUtils.equalsIgnoreCase(user, request.getRequestedBy())) {
			throw new PRScanBypassException("Only the requester can withdraw a request.");
		}
		long now = clock.millis();
		claim(request, BypassRequestStatus.WITHDRAWN, user, now, null);
		request.decide(BypassRequestStatus.WITHDRAWN, user, now, null);
		LOG.info("Bypass request {} withdrawn by {}", request.getId(), user);
	}

	/**
	 * Closes the request in the database only if it is still pending, so of two concurrent
	 * decisions exactly one wins.
	 *
	 * @throws PRScanBypassException if someone else decided it first
	 */
	private void claim(PullRequestBypassRequestEntity request, BypassRequestStatus outcome,
			String user, long when, String note) {
		if (requestRepository.close(request.getId(), outcome, user, when, note,
				BypassRequestStatus.PENDING) == 0) {
			throw new PRScanBypassException("This request was already decided.");
		}
	}

	private static String pendingKeyOf(PullRequestBypassRequestEntity request) {
		return PullRequestBypassRequestEntity.pendingKey(request.getApiLabel(),
				request.getRepoName(), request.getPrId());
	}

	/**
	 * Never throws: an unknown scan has no request.
	 *
	 * @param scanId a scan of the pull request
	 * @param viewer who is looking
	 * @return the pending request, if any, and whether the viewer made it
	 */
	public RequestState stateFor(long scanId, String viewer) {
		try {
			return pending(bypassService.findScan(scanId).getContainer())
					.map(request -> new RequestState(request,
							StringUtils.equalsIgnoreCase(viewer, request.getRequestedBy())))
					.orElse(RequestState.NONE);
		} catch (RuntimeException e) {
			return RequestState.NONE;
		}
	}

	/**
	 * The requests list on the bypasses page. A pending request whose pull request was scanned
	 * again since is superseded first, so the list never offers to approve a stale request.
	 *
	 * @return the newest requests, whatever their status, newest first
	 */
	public List<PullRequestBypassRequestEntity> recentRequests() {
		requestRepository.findByPendingKeyIsNotNull().forEach(this::supersedeIfStale);
		return requestRepository.findTop200ByOrderByCreatedAtDesc();
	}

	private void supersedeIfStale(PullRequestBypassRequestEntity request) {
		try {
			pending(bypassService.findScan(request.getScanId()).getContainer());
		} catch (RuntimeException e) {
			// Listed as pending; approving it is refused with the reason.
			LOG.warn("Could not check whether bypass request {} is still current",
					request.getId(), e);
		}
	}

	private PullRequestBypassRequestEntity pendingFor(long scanId) {
		return pending(bypassService.findScan(scanId).getContainer()).orElseThrow(
				() -> new PRScanBypassException("No pending bypass request on this pull request."));
	}

	/**
	 * @return the PR's pending request, after superseding it if a newer scan replaced its scan
	 */
	private Optional<PullRequestBypassRequestEntity> pending(PullRequestContainerEntity container) {
		Optional<PullRequestBypassRequestEntity> pending = requestRepository
				.findFirstByApiLabelAndRepoNameAndPrIdAndStatusOrderByCreatedAtDesc(
						container.getApiLabel(), container.getRepoName(), container.getPrId(),
						BypassRequestStatus.PENDING);
		if (pending.isPresent()
				&& pending.get().getScanId() != PRScanBypassService.latestScanId(container)) {
			long now = clock.millis();
			requestRepository.close(pending.get().getId(), BypassRequestStatus.SUPERSEDED, null,
					now, null, BypassRequestStatus.PENDING);
			pending.get().decide(BypassRequestStatus.SUPERSEDED, null, now, null);
			LOG.info("Bypass request {} superseded by a newer scan", pending.get().getId());
			return Optional.empty();
		}
		return pending;
	}

	private PullRequestBypassRequestEntity newRequest(PullRequestScanEntity scan, String user,
			String reason) {
		PullRequestContainerEntity container = scan.getContainer();
		PullRequestBypassRequestEntity request = new PullRequestBypassRequestEntity();
		request.setApiLabel(container.getApiLabel());
		request.setRepoName(container.getRepoName());
		request.setPrId(container.getPrId());
		request.setScanId(scan.getId());
		request.setRequestedBy(user);
		request.setReason(reason);
		request.setCreatedAt(clock.millis());
		request.setPendingKey(pendingKeyOf(request));
		return request;
	}

	/**
	 * @return the requester's reason naming the requester, cut to fit the bypass reason column
	 */
	private static String approvedReason(PullRequestBypassRequestEntity request) {
		String suffix = " (requested by " + requester(request) + ")";
		return StringUtils.abbreviate(request.getReason(),
				PullRequestBypassEntity.MAX_REASON_LENGTH - suffix.length()) + suffix;
	}

	/**
	 * @return who asked, saying so when the name is an SCM one rather than a Watchtower login
	 */
	static String requester(PullRequestBypassRequestEntity request) {
		return request.isFromPullRequestComment()
				? request.getRequestedBy() + " via a pull request comment"
				: request.getRequestedBy();
	}

	private void raiseRequested(PullRequestScanEntity scan,
			PullRequestBypassRequestEntity request) {
		PullRequestContainerEntity container = scan.getContainer();
		try {
			alertService.raise(new AlertEvent(PR_BYPASS_REQUESTED, container.getApiLabel(),
					container.getRepoName(), "Bypass requested on pull request #"
							+ container.getPrId() + " by " + requester(request),
					PRScanBypassService.reportLink(publicUrl, scan.getId()),
					String.join("\u0000", "bypass", container.getApiLabel(),
							container.getRepoName(), container.getPrId()),
					List.of(new AlertItem("bypass-request\u0000" + request.getId() + "\u0000"
							+ request.getCreatedAt(), null, "Reason: "
									+ PRScanBypassService.sentence(request.getReason())
									+ " Approve or decline it on the scan report."))));
		} catch (RuntimeException e) {
			LOG.warn("Could not raise the bypass request alert for scan {}", scan.getId(), e);
		}
	}
}
