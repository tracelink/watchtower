package com.tracelink.appsec.watchtower.core.scan.scm.pr.controller;

import java.util.List;

import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.api.APIIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.api.APIIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.api.ApiFactoryService;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.ManualPullRequest;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.service.PRScanningService;

/**
 * Controller for handling the scanner. Handles displaying scan status, sending a new scan manually,
 * and pause/quiesce/resume functions
 *
 * @author csmith
 */
@Controller
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_SUBMIT_NAME + "')")
public class PRScanController {
	private static final Logger LOG = LoggerFactory.getLogger(PRScanController.class);

	private PRScanningService scanService;

	private PRScanResultService prScanResultService;

	private ApiFactoryService scannerFactoryService;

	private APIIntegrationService apiIntegrationService;

	public PRScanController(@Autowired PRScanningService scanService,
			@Autowired PRScanResultService prScanResultService,
			@Autowired ApiFactoryService scannerFactoryService,
			@Autowired APIIntegrationService apiIntegrationService) {
		this.scanService = scanService;
		this.prScanResultService = prScanResultService;
		this.scannerFactoryService = scannerFactoryService;
		this.apiIntegrationService = apiIntegrationService;
	}

	@GetMapping("/scan")
	public WatchtowerModelAndView scan() {
		WatchtowerModelAndView mav = new WatchtowerModelAndView("pull_requests/submitscan");

		List<APIIntegrationEntity> types = apiIntegrationService.getAllSettings();

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
