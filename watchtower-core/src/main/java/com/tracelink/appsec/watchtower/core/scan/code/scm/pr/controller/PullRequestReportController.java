package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.controller;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.BypassState;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PRBypassRequestService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.BypassedFinding;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PRScanBypassException;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PRScanBypassService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResult;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResultViolation;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.scan.presentation.FindingAction;
import com.tracelink.appsec.watchtower.core.scan.presentation.FindingContext;
import com.tracelink.appsec.watchtower.core.scan.presentation.FindingPresentationModel;
import com.tracelink.appsec.watchtower.core.scan.presentation.IFindingActionProvider;
import com.tracelink.appsec.watchtower.core.scan.presentation.FindingVerification;
import com.tracelink.appsec.watchtower.core.verification.ILiveVerifier;
import com.tracelink.appsec.watchtower.core.verification.LiveVerificationStatus;

/**
 * Controller for viewing the report of a pull request scan, and for requesting a live check of a
 * reported secret where a module offers one ({@link ILiveVerifier}).
 *
 * @author csmith
 */
@Controller
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "')")
public class PullRequestReportController {
	@Autowired(required = false)
	private com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService remoteAssessments;
    @Autowired private com.tracelink.appsec.watchtower.core.scan.code.report.ScanReportExporter combinedExports;
	@Autowired(required = false)
	private com.tracelink.appsec.watchtower.core.feedback.FindingFeedbackService feedbackService;
    @GetMapping("/scan/report/{id}/export")
    public void export(@PathVariable long id, @RequestParam(defaultValue="json") String format, jakarta.servlet.http.HttpServletResponse response) throws java.io.IOException {
        combinedExports.export("pull_request", id, format, response);
    }
	private static final Logger LOG = LoggerFactory.getLogger(PullRequestReportController.class);

	/** The {@code from} value of a decision made on the bypasses page's requests list. */
	private static final String FROM_REQUESTS_LIST = "requests";

	private final PRScanResultService scanResultService;

	private final ObjectProvider<ILiveVerifier> verifiers;

	private final PRScanBypassService bypassService;

	private final ObjectProvider<IFindingActionProvider> actionProviders;

	private final PRBypassRequestService requestService;

	public PullRequestReportController(@Autowired PRScanResultService scanResultService,
			@Autowired ObjectProvider<ILiveVerifier> verifiers,
			@Autowired PRScanBypassService bypassService,
			@Autowired ObjectProvider<IFindingActionProvider> actionProviders,
			@Autowired PRBypassRequestService requestService) {
		this.scanResultService = scanResultService;
		this.verifiers = verifiers;
		this.bypassService = bypassService;
		this.actionProviders = actionProviders;
		this.requestService = requestService;
	}

	@GetMapping("/scan/report/{id}")
	public WatchtowerModelAndView getPRReport(@PathVariable String id,
			Authentication authentication, RedirectAttributes redirectAttributes) {
		WatchtowerModelAndView mav = new WatchtowerModelAndView("pull_requests/scanreport");
		PRScanResult scanResult = scanResultService.getScanResultForScanId(id);
		if (scanResult == null) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Unknown ID");
			mav.setViewName("redirect:/scan");
		} else {
			mav.addObject("result", scanResult);
			mav.addObject("findings", com.tracelink.appsec.watchtower.core.scan.presentation.RemoteReportModel.add(mav, "pull_request", Long.parseLong(id), remoteAssessments, FindingPresentationModel.fromPullRequest(
					scanResult.getViolations(),
					verificationsFor(scanResult.getViolations(), authentication),
					actionsFor(scanResult, authentication)).stream()
					// A live secret is the most urgent finding on the page.
					.sorted(Comparator.comparing(finding -> !isLive(finding)))
					.toList()));
			markReviewed(mav, scanResult.getId());
			mav.addObject("verifyUrl", "/scan/report/" + scanResult.getId() + "/verify");
			addBypassModel(mav, scanResult, authentication);
			mav.addScriptReference("/scripts/scan_report.js");
			mav.addScriptReference("/scripts/workspace-resizer.js");
			mav.addScriptReference("/scripts/finding-workspace.js");
			mav.addScriptReference("/scripts/scan-report-code.js");
			mav.addScriptReference("/scripts/pr-bypass.js");
		}
		return mav;
	}

	/**
	 * The report of a pull request's newest scan. PR comments link here because a scan's own id
	 * is not known yet when the comment is posted.
	 */
	@GetMapping("/scan/report/latest")
	public String latestReport(@RequestParam String apiLabel, @RequestParam String repo,
			@RequestParam String prId, RedirectAttributes redirectAttributes) {
		PullRequestContainerEntity container =
				scanResultService.getPullRequestByLabelRepoAndId(apiLabel, repo, prId);
		OptionalLong latest = container == null || container.getScans() == null
				? OptionalLong.empty()
				: container.getScans().stream().mapToLong(PullRequestScanEntity::getId).max();
		if (latest.isEmpty()) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"No scan found for that pull request.");
			return "redirect:/scan";
		}
		return "redirect:/scan/report/" + latest.getAsLong();
	}

	/**
	 * Queues a live check of one finding's secret. The numeric id keeps the redirect a plain
	 * report path.
	 */
	@PostMapping("/scan/report/{id}/verify")
	public String requestVerification(@PathVariable long id, @RequestParam long violationId,
			Authentication authentication, RedirectAttributes redirectAttributes) {
		ILiveVerifier verifier = verifiers.getIfUnique();
		if (verifier == null || !hasAuthority(authentication, verifier.getPrivilegeName())) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"You are not allowed to verify secrets.");
			return "redirect:/scan/report/" + id;
		}
		try {
			LiveVerificationStatus status =
					verifier.request(id, violationId, authentication.getName());
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					status == LiveVerificationStatus.PENDING
							? "Live verification queued. Reload this report in a minute."
							: "Live verification: " + status.getLabel());
		} catch (IllegalArgumentException e) {
			// The verifier's own validation messages, e.g. "Unknown finding"
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
		}
		return "redirect:/scan/report/" + id;
	}

	/**
	 * Stops Watchtower blocking the scan's pull request for the findings it reported (§4.12).
	 */
	@PostMapping("/scan/report/{id}/bypass")
	@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "') and hasAuthority('"
			+ CorePrivilege.PR_SCAN_BYPASS_NAME + "')")
	public String bypass(@PathVariable long id, @RequestParam(required = false) String reason,
   @RequestParam(defaultValue="OTHER") com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.BypassReasonCode reasonCode,
   Authentication authentication, RedirectAttributes redirectAttributes) {
		try {
			if (reasonCode==com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.BypassReasonCode.OTHER ? bypassService.bypass(id,authentication.getName(),reason) : bypassService.bypass(id, authentication.getName(), reason,reasonCode)) {
				redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						"Blocking bypassed. The pull request was updated and commented on.");
			} else {
				redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
						"Blocking bypassed, but the pull request could not be updated. The next"
								+ " scan applies the bypass.");
			}
		} catch (PRScanBypassException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
		}
		return "redirect:/scan/report/" + id;
	}

 public String bypass(long id,String reason,Authentication a,RedirectAttributes r){return bypass(id,reason,com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.BypassReasonCode.OTHER,a,r);}

	/**
	 * Ends the pull request's bypass, so its blocking findings block again.
	 */
	@PostMapping("/scan/report/{id}/bypass/revoke")
	@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "') and hasAuthority('"
			+ CorePrivilege.PR_SCAN_BYPASS_NAME + "')")
	public String revokeBypass(@PathVariable long id, Authentication authentication,
			RedirectAttributes redirectAttributes) {
		try {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					bypassService.revoke(id, authentication.getName())
							? "Bypass revoked. Watchtower is rescanning the pull request."
							: "Bypass revoked. Blocking resumes on the next push.");
		} catch (PRScanBypassException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
		}
		return "redirect:/scan/report/" + id;
	}

	/**
	 * Asks someone with the bypass privilege to bypass the pull request (§4.17). Any viewer may.
	 */
	@PostMapping("/scan/report/{id}/bypass/request")
	public String requestBypass(@PathVariable long id,
			@RequestParam(required = false) String reason,
   @RequestParam(defaultValue="OTHER") com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.BypassReasonCode reasonCode,
   Authentication authentication, RedirectAttributes redirectAttributes) {
		return withRefusalFlash("redirect:/scan/report/" + id, redirectAttributes, () -> {
			if(reasonCode==com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.BypassReasonCode.OTHER)requestService.request(id,authentication.getName(),reason);else requestService.request(id, authentication.getName(), reason,reasonCode);
			return "Bypass requested. Approvers have been alerted.";
		});
	}

 public String requestBypass(long id,String reason,Authentication a,RedirectAttributes r){return requestBypass(id,reason,com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.BypassReasonCode.OTHER,a,r);}

	@PostMapping("/scan/report/{id}/bypass/request/approve")
	@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "') and hasAuthority('"
			+ CorePrivilege.PR_SCAN_BYPASS_NAME + "')")
	public String approveBypassRequest(@PathVariable long id,
			@RequestParam(required = false) String from, Authentication authentication,
			RedirectAttributes redirectAttributes) {
		try {
			if (requestService.approve(id, authentication.getName())) {
				redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						"Request approved: blocking bypassed, and the pull request was updated.");
			} else {
				redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
						"Request approved and blocking bypassed, but the pull request could not"
								+ " be updated. The next scan applies the bypass.");
			}
		} catch (PRScanBypassException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
		}
		return afterDecision(id, from);
	}

	@PostMapping("/scan/report/{id}/bypass/request/decline")
	@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "') and hasAuthority('"
			+ CorePrivilege.PR_SCAN_BYPASS_NAME + "')")
	public String declineBypassRequest(@PathVariable long id,
			@RequestParam(required = false) String note,
			@RequestParam(required = false) String from, Authentication authentication,
			RedirectAttributes redirectAttributes) {
		return withRefusalFlash(afterDecision(id, from), redirectAttributes, () -> {
			requestService.decline(id, authentication.getName(), note);
			return "Bypass request declined.";
		});
	}

	@PostMapping("/scan/report/{id}/bypass/request/withdraw")
	public String withdrawBypassRequest(@PathVariable long id,
			@RequestParam(required = false) String from, Authentication authentication,
			RedirectAttributes redirectAttributes) {
		return withRefusalFlash(afterDecision(id, from), redirectAttributes, () -> {
			requestService.withdraw(id, authentication.getName());
			return "Bypass request withdrawn.";
		});
	}

	/**
	 * @param from "requests" when the decision was made on the bypasses page's requests list;
	 *             anything else is ignored, so it can't redirect elsewhere
	 * @return where to go after deciding a request: back to that list, or to the report
	 */
	private static String afterDecision(long id, String from) {
		return FROM_REQUESTS_LIST.equals(from) ? "redirect:/scan/bypasses?view=requests"
				: "redirect:/scan/report/" + id;
	}

	/**
	 * Runs a request action and flashes its message, or the refusal's.
	 *
	 * @return the redirect, unchanged
	 */
	private static String withRefusalFlash(String redirect, RedirectAttributes redirectAttributes,
			Supplier<String> action) {
		try {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					action.get());
		} catch (PRScanBypassException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
		}
		return redirect;
	}

	/**
	 * Adds what the report shows about bypassing. A failure to read it hides the bypass section
	 * rather than failing the report.
	 */
	private void addBypassModel(WatchtowerModelAndView mav, PRScanResult scanResult,
			Authentication authentication) {
		boolean canManageBypass = hasAuthority(authentication, CorePrivilege.PR_SCAN_BYPASS_NAME);
		BypassState state;
		try {
			// Every viewer may request a bypass, so everyone needs to see why it is refused.
			state = bypassService.stateFor(scanResult.getId(), true);
		} catch (RuntimeException e) {
			LOG.warn("Could not load the bypass state of scan {}", scanResult.getId(), e);
			state = BypassState.NONE;
		}
		String base = "/scan/report/" + scanResult.getId() + "/bypass";
		mav.addObject("bypass", state);
		mav.addObject("bypassRequest", requestService.stateFor(scanResult.getId(),
				authentication == null ? null : authentication.getName()));
		mav.addObject("canManageBypass", canManageBypass);
		mav.addObject("bypassUrl", base);
		mav.addObject("revokeBypassUrl", base + "/revoke");
		mav.addObject("requestBypassUrl", base + "/request");
		mav.addObject("bypassFindings", bypassFindings(scanResult.getViolations()));
		mav.addObject("bypassCoverage",
				com.tracelink.appsec.watchtower.core.scan.presentation.BypassCoverage.of(scanResult.getViolations()));
	}

	/**
	 * Marks each finding with its latest human judgment for the list's review marker, with one
	 * query for the whole scan. A failure only drops the markers; the report still renders.
	 */
	@SuppressWarnings("unchecked")
	private void markReviewed(WatchtowerModelAndView mav, long scanId) {
		Object findings = mav.getModel().get("findings");
		if (feedbackService == null || !(findings instanceof List<?> list) || list.isEmpty()) {
			return;
		}
		try {
			Map<String, String> judgments = new java.util.HashMap<>();
			feedbackService.forScan("pull_request", scanId).forEach(row -> judgments.put(
					String.valueOf(row.get("finding_key")), String.valueOf(row.get("judgment"))));
			((List<FindingPresentationModel>) list).forEach(finding -> finding.withReview(
					finding.getFeedbackKey() == null ? null : judgments.get(finding.getFeedbackKey())));
		} catch (RuntimeException e) {
			LOG.warn("Could not load review markers for scan {}", scanId, e);
		}
	}

	/**
	 * @return the distinct rule and file of each finding, as the bypass dialog lists them
	 */
	private static List<BypassedFinding> bypassFindings(List<PRScanResultViolation> violations) {
		if (violations == null) {
			return List.of();
		}
		return violations.stream()
				.map(v -> new BypassedFinding(v.getViolationName(), v.getFileName()))
				.distinct()
				.sorted(Comparator.comparing(BypassedFinding::getFilePath,
						Comparator.nullsFirst(Comparator.naturalOrder()))
						.thenComparing(BypassedFinding::getRuleName,
								Comparator.nullsFirst(Comparator.naturalOrder())))
				.toList();
	}

	/**
	 * @return each violation's module action (the first a provider offers), or null. A failing
	 *         provider is skipped rather than failing the report.
	 */
	private Function<PRScanResultViolation, FindingAction> actionsFor(PRScanResult scanResult,
			Authentication authentication) {
		List<IFindingActionProvider> providers = actionProviders.orderedStream().toList();
		if (providers.isEmpty()) {
			return violation -> null;
		}
		return violation -> {
			FindingContext context = new FindingContext(scanResult.getApiLabel(),
					scanResult.getRepoName(), violation.getViolationName(),
					violation.getFileName(), violation.getLineNumber());
			for (IFindingActionProvider provider : providers) {
				try {
					Optional<FindingAction> action = provider.actionFor(context, authentication);
					if (action.isPresent()) {
						return action.get();
					}
				} catch (RuntimeException e) {
					LOG.warn("A finding action provider failed on scan {}", scanResult.getId(), e);
				}
			}
			return null;
		};
	}

	/**
	 * @return each violation's "Verify live" state, or null where no verifier applies. A failure
	 *         to read statuses hides the action rather than failing the report.
	 */
	private Function<PRScanResultViolation, FindingVerification> verificationsFor(
			List<PRScanResultViolation> violations, Authentication authentication) {
		ILiveVerifier verifier = verifiers.getIfUnique();
		if (verifier == null || violations == null) {
			return violation -> null;
		}
		Set<Long> supported = violations.stream()
				.filter(violation -> verifier.supports(violation.getViolationName()))
				.map(PRScanResultViolation::getViolationId)
				.collect(Collectors.toUnmodifiableSet());
		if (supported.isEmpty()) {
			return violation -> null;
		}
		Map<Long, LiveVerificationStatus> statuses;
		try {
			statuses = verifier.getStatuses(supported);
		} catch (RuntimeException e) {
			LOG.warn("Could not load live verification statuses", e);
			return violation -> null;
		}
		boolean canRequest = hasAuthority(authentication, verifier.getPrivilegeName());
		return violation -> supported.contains(violation.getViolationId())
				? new FindingVerification(violation.getViolationId(),
						statuses.get(violation.getViolationId()), canRequest)
				: null;
	}

	private static boolean isLive(FindingPresentationModel finding) {
		return finding.hasVerification()
				&& finding.getVerification().status() == LiveVerificationStatus.LIVE;
	}

	private static boolean hasAuthority(Authentication authentication, String authority) {
		return authentication != null && authentication.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.anyMatch(granted -> granted.equals(authority));
	}
}
