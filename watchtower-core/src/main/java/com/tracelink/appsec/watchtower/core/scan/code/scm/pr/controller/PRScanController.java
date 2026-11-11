package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.controller;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.ManualPullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanSubmitResult;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanningService;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.presentation.HomeActivityItem;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryFilter;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryService;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.web.bind.annotation.ResponseBody;
import java.util.List;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Controller for handling the scanner. Handles displaying scan status, sending a new scan manually,
 * and pause/quiesce/resume functions
 *
 * @author csmith
 */
@Controller
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_SUBMIT_NAME + "')")
public class PRScanController {

	private final PRScanningService scanService;
	private final PRScanResultService prScanResultService;
	private final ApiIntegrationService apiIntegrationService;
	private final RepositoryService repositoryService;

	public PRScanController(@Autowired PRScanningService scanService,
			@Autowired PRScanResultService prScanResultService,
			@Autowired ApiIntegrationService apiIntegrationService,
			@Autowired RepositoryService repositoryService) {
		this.scanService = scanService;
		this.prScanResultService = prScanResultService;
		this.apiIntegrationService = apiIntegrationService;
		this.repositoryService = repositoryService;
	}

	/** One suggestion for the New scan form's Repository field. */
	public record RepositorySuggestion(String name, String project, String status) {
	}

	private static final int SUGGESTIONS = 8;

	/**
	 * Repositories Watchtower knows for a pull request integration whose name contains the typed
	 * text, for the New scan form's searchable Repository field. Unknown integrations get nothing.
	 */
	@GetMapping(value = "/scan/repositories", produces = "application/json")
	@ResponseBody
	public List<RepositorySuggestion> repositories(@RequestParam String apiLabel,
			@RequestParam(defaultValue = "") String q) {
		boolean known = apiIntegrationService.getAllSettings().stream()
				.anyMatch(api -> api.getScanType() == CodeScanType.PULL_REQUEST && apiLabel.equals(api.getApiLabel()));
		if (!known) {
			return List.of();
		}
		RepositoryFilter filter = new RepositoryFilter(q, null, null, null, null, null);
		return repositoryService.list(CodeScanType.PULL_REQUEST, apiLabel, filter,
				PageRequest.of(0, SUGGESTIONS, Sort.by("repoName"))).stream()
				.map(repo -> new RepositorySuggestion(repo.getRepoName(), repo.getProjectKey(),
						!repo.isEnabled() ? "Gone" : repo.isScanningPaused() ? "Paused" : "Active"))
				.toList();
	}

	private static final int RECENT_SCANS = 5;

	@GetMapping("/scan")
	public WatchtowerModelAndView scan() {
		WatchtowerModelAndView mav = new WatchtowerModelAndView("pull_requests/submitscan");

		List<ApiIntegrationEntity> types = apiIntegrationService.getAllSettings().stream()
				.filter(api -> api.getScanType() == CodeScanType.PULL_REQUEST).toList();

		mav.addObject("numScansQueued", scanService.getTaskNumInQueue());
		mav.addObject("numScansInProgress", scanService.getTaskNumActive());
		mav.addObject("scanStatePaused", scanService.isPaused());
		mav.addObject("scanStateQuiesced", scanService.isQuiesced());
		mav.addObject("scms", types);
		List<PullRequestScanEntity> lastScans =
				prScanResultService.getLastScans(RECENT_SCANS);
		mav.addObject("lastScans", lastScans);
		// The same recent-scans table as Home, plus each pull request's Open/Resolved state.
		mav.addObject("recentActivity", lastScans.stream()
				.map(HomeActivityItem::fromPullRequest).toList());
		mav.addScriptReference("/scripts/scan-submission.js");
		mav.addScriptReference("/scripts/repo-suggest.js");
		return mav;
	}

	@PostMapping("/scan")
	public String submitScan(@Valid @ModelAttribute ManualPullRequest pullRequest,
			RedirectAttributes redirectAttributes) {
		if (org.apache.commons.lang3.StringUtils.isBlank(pullRequest.getRepo())
				|| org.apache.commons.lang3.StringUtils.isBlank(pullRequest.getPrid())) {
			// Without these the scan was queued for pull request "null" and failed later
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Enter the repository and the pull request number.");
			return "redirect:/scan";
		}
		pullRequest.setPrid(pullRequest.getPrid().trim());
		try {
			PullRequest pr = pullRequest.createPR();
			// A pull request that does not exist is refused here, with the reason, instead of
			// being reported as queued and then never appearing
			scanService.requirePullRequestExists(pr);
			// Reporting "Successfully Queued Scan" for a dropped scan left users waiting
			// for results that were never coming.
			PRScanSubmitResult result = scanService.doPullRequestScan(pr);
			redirectAttributes.addFlashAttribute(
					result.isAccepted() ? WatchtowerModelAndView.SUCCESS_NOTIFICATION
							: WatchtowerModelAndView.FAILURE_NOTIFICATION,
					result.getDescription());
		} catch (Exception e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
		}
		return "redirect:/scan";
	}

	@PostMapping("/scan/pause")
	@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_ADMIN_NAME + "')")
	public String pauseScanner(@RequestParam boolean pause) {
		if (pause) {
			scanService.pauseExecution();
		} else {
			scanService.resumeExecution();
		}
		return "redirect:/scan";
	}

	@PostMapping("/scan/quiesce")
	@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_ADMIN_NAME + "')")
	public String quiesceScanner(@RequestParam boolean quiesce) {
		if (quiesce) {
			scanService.quiesce();
		} else {
			scanService.unQuiesce();
		}
		return "redirect:/scan";
	}

}
