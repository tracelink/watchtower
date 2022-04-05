package com.tracelink.appsec.watchtower.core.scan.code.upload.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.scan.code.upload.service.UploadScanResultService;
import com.tracelink.appsec.watchtower.core.scan.code.upload.service.UploadScanningService;

/**
 * Controller for handling the scanner. Handles displaying scan status, sending a new scan manually,
 * and pause/quiesce/resume functions
 *
 * @author csmith
 */
@Controller
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_SUBMIT_NAME + "')")
public class UploadScanController {

	private UploadScanningService scanService;

	private UploadScanResultService scanResultService;

	private RulesetService rulesetService;

	public UploadScanController(@Autowired UploadScanningService scanService,
			@Autowired UploadScanResultService scanResultService,
			@Autowired RulesetService rulesetService) {
		this.scanService = scanService;
		this.scanResultService = scanResultService;
		this.rulesetService = rulesetService;
	}

	@GetMapping("/uploadscan")
	public WatchtowerModelAndView scan() {
		WatchtowerModelAndView mav = new WatchtowerModelAndView("upload_scan/submitscan");
		mav.addObject("numScansQueued", scanService.getTaskNumInQueue());
		mav.addObject("numScansInProgress", scanService.getTaskNumActive());
		mav.addObject("scanStatePaused", scanService.isPaused());
		mav.addObject("scanStateQuiesced", scanService.isQuiesced());
		mav.addObject("lastScans", scanResultService.getLastScans(100));
		mav.addObject("rulesets", rulesetService.getRulesets());
		mav.addObject("defaultRuleset", rulesetService.getDefaultRuleset());
		return mav;
	}

	@PostMapping("/uploadscan/pause")
	@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_ADMIN_NAME + "')")
	public String pauseScanner(@RequestParam boolean pause) {
		if (pause) {
			scanService.pauseExecution();
		} else {
			scanService.resumeExecution();
		}
		return "redirect:/uploadscan";
	}

	@PostMapping("/uploadscan/quiesce")
	@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_ADMIN_NAME + "')")
	public String quiesceScanner(@RequestParam boolean quiesce) {
		if (quiesce) {
			scanService.quiesce();
		} else {
			scanService.unQuiesce();
		}
		return "redirect:/uploadscan";
	}

}
