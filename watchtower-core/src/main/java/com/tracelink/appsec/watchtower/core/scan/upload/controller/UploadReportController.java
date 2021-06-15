package com.tracelink.appsec.watchtower.core.scan.upload.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.upload.entity.UploadScanContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.upload.service.UploadScanResultService;

/**
 * Controller for handling viewing reports for a given upload scan
 *
 * @author csmith
 */
@Controller
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "')")
public class UploadReportController {
	private UploadScanResultService scanResultService;

	public UploadReportController(@Autowired UploadScanResultService scanResultService) {
		this.scanResultService = scanResultService;
	}

	@GetMapping("/uploadscan/report/{ticket}")
	public WatchtowerModelAndView getUploadReport(@PathVariable String ticket,
			RedirectAttributes redirectAttributes) {
		WatchtowerModelAndView mav = new WatchtowerModelAndView("upload_scan/scanreport");
		UploadScanContainerEntity scanEntity = scanResultService.findUploadScanByTicket(ticket);
		if (scanEntity == null) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Unknown ticket");
			mav.setViewName("redirect:/uploadscan");
		} else {
			mav.addObject("result", scanResultService.generateResultForTicket(ticket));
			mav.addScriptReference("/scripts/scan_report.js");
		}
		return mav;
	}

}
