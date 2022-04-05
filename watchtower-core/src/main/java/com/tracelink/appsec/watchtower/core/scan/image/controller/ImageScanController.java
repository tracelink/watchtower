package com.tracelink.appsec.watchtower.core.scan.image.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.api.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageScanningService;

@Controller
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_SUBMIT_NAME + "')")
public class ImageScanController {

	private ImageScanningService scanService;

	public ImageScanController(@Autowired ImageScanningService scanService) {
		this.scanService = scanService;
	}

	@GetMapping("/imagescan")
	public WatchtowerModelAndView scan() {
		WatchtowerModelAndView mav = new WatchtowerModelAndView("upload_scan/submitscan");

		mav.addObject("numScansQueued", scanService.getTaskNumInQueue());
		mav.addObject("numScansInProgress", scanService.getTaskNumActive());
		mav.addObject("scanStatePaused", scanService.isPaused());
		mav.addObject("scanStateQuiesced", scanService.isQuiesced());
		return mav;
	}

	@PostMapping("/imagescan")
	public String submitScan(@RequestParam String apiLabel,
			@RequestParam String imageName,
			@RequestParam String tagName,
			RedirectAttributes redirectAttributes) {
		try {
			ImageScan image = new ImageScan(apiLabel);
			image.setImageName(imageName);
			image.setImageTag(tagName);
			scanService.doImageScan(image);
		} catch (ApiIntegrationException e) {

		}
		return "redirect:/imagescan";
	}

	@PostMapping("/imagescan/pause")
	@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_ADMIN_NAME + "')")
	public String pauseScanner(@RequestParam boolean pause) {
		if (pause) {
			scanService.pauseExecution();
		} else {
			scanService.resumeExecution();
		}
		return "redirect:/imagescan";
	}

	@PostMapping("/imagescan/quiesce")
	@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_ADMIN_NAME + "')")
	public String quiesceScanner(@RequestParam boolean quiesce) {
		if (quiesce) {
			scanService.quiesce();
		} else {
			scanService.unQuiesce();
		}
		return "redirect:/imagescan";
	}
}
