package com.tracelink.appsec.watchtower.core.scan.upload.controller;

import java.io.IOException;
import java.nio.file.Path;
import java.security.Principal;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.scan.upload.UploadScan;
import com.tracelink.appsec.watchtower.core.scan.upload.service.UploadScanResultService;
import com.tracelink.appsec.watchtower.core.scan.upload.service.UploadScanningService;

/**
 * Controller for handling the scanner. Handles displaying scan status, sending a new scan manually,
 * and pause/quiesce/resume functions
 *
 * @author csmith
 */
@Controller
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_SUBMIT_NAME + "')")
public class UploadScanController {
	private static final Logger LOG = LoggerFactory.getLogger(UploadScanController.class);

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

	@PostMapping("/uploadscan")
	public String submitScan(@RequestParam Optional<String> name,
			@RequestParam Optional<String> ruleset,
			@RequestBody MultipartFile uploadFile,
			Principal userPrincipal,
			RedirectAttributes redirectAttributes) {
		String uploadName = name.orElse(uploadFile.getOriginalFilename());
		String rulesetName = ruleset.orElse(null);

		try {
			Path zipLocation = scanService.copyToLocation(uploadFile);

			UploadScan upload = new UploadScan();
			upload.setName(uploadName);
			upload.setRuleSetName(rulesetName);
			upload.setFilePath(zipLocation);
			upload.setUser(userPrincipal.getName());
			upload.setSubmitDate(System.currentTimeMillis());
			String ticket = scanService.doUploadScan(upload);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully added scan. Ticket ID: " + ticket);
		} catch (IOException e) {
			LOG.error("Error copying the file", e);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Error copying the file: " + e.getMessage());
		} catch (ScanRejectedException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
		}

		return "redirect:/uploadscan";
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
