package com.tracelink.appsec.watchtower.core.scan.image.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageScanResult;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageScanResultService;

/**
 * Controller for handling viewing reports for a given image scan
 *
 * @author csmith
 */
@Controller
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "')")
public class ImageReportController {
	private ImageScanResultService scanResultService;

	public ImageReportController(@Autowired ImageScanResultService scanResultService) {
		this.scanResultService = scanResultService;
	}

	@GetMapping("/imagescan/report")
	public WatchtowerModelAndView getImageScanReportByCoordinates(@RequestParam String registry,
			@RequestParam String imageName, @RequestParam String imageTag,
			RedirectAttributes redirectAttributes) {
		WatchtowerModelAndView mav = new WatchtowerModelAndView("image_scan/scanreport");

		ImageScanResult res =
				scanResultService.generateResultForCoordinates(registry, imageName, imageTag);
		if (res.equals(ImageScanResultService.UNKNOWN_RESULT)) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Unknown Image Coordinates");
			mav.setViewName("redirect:/imagescan");
		} else {
			mav.addObject("result", res);
			mav.addScriptReference("/scripts/scan_report.js");
		}

		return mav;
	}

}
