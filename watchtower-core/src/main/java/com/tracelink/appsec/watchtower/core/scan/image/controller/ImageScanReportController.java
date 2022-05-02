package com.tracelink.appsec.watchtower.core.scan.image.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageScanEntity;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageScanResultService;

/**
 * Controller for getting information about image scan reports
 * 
 * @author csmith
 *
 */
@Controller
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "')")
@RequestMapping("/imagescan/report")
public class ImageScanReportController {
	private ImageScanResultService scanResultService;

	public ImageScanReportController(@Autowired ImageScanResultService scanResultService) {
		this.scanResultService = scanResultService;
	}

	@GetMapping("{id}")
	public WatchtowerModelAndView getImageReport(@PathVariable long id,
			RedirectAttributes redirectAttributes) {
		WatchtowerModelAndView mav = new WatchtowerModelAndView("image_scan/scanreport");
		ImageScanEntity scanEntity = scanResultService.findById(id);
		if (scanEntity == null) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Unknown ID");
			mav.setViewName("redirect:/imagescan");
		} else {
			mav.addObject("result", scanResultService.generateResultForScan(scanEntity));
			mav.addScriptReference("/scripts/scan_report.js");
		}
		return mav;
	}

}
