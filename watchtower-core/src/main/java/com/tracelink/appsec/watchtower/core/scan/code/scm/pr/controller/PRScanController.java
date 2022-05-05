package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.controller;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.ManualPullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanningService;
import java.util.List;
import javax.validation.Valid;
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

	public PRScanController(@Autowired PRScanningService scanService,
			@Autowired PRScanResultService prScanResultService,
			@Autowired ApiIntegrationService apiIntegrationService) {
		this.scanService = scanService;
		this.prScanResultService = prScanResultService;
		this.apiIntegrationService = apiIntegrationService;
	}

	@GetMapping("/scan")
	public WatchtowerModelAndView scan() {
		WatchtowerModelAndView mav = new WatchtowerModelAndView("pull_requests/submitscan");

		List<ApiIntegrationEntity> types = apiIntegrationService.getAllSettings();

		mav.addObject("numScansQueued", scanService.getTaskNumInQueue());
		mav.addObject("numScansInProgress", scanService.getTaskNumActive());
		mav.addObject("scanStatePaused", scanService.isPaused());
		mav.addObject("scanStateQuiesced", scanService.isQuiesced());
		mav.addObject("scms", types);
		mav.addObject("lastScans", prScanResultService.getLastScans(100));
		return mav;
	}

	@PostMapping("/scan")
	public String submitScan(@Valid @ModelAttribute ManualPullRequest pullRequest,
			RedirectAttributes redirectAttributes) {
		try {
			PullRequest pr = pullRequest.createPR();
			scanService.doPullRequestScan(pr);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully Queued Scan");
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
