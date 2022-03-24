package com.tracelink.appsec.watchtower.core.scan.code.pr.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.code.pr.result.PRScanResult;
import com.tracelink.appsec.watchtower.core.scan.code.pr.service.PRScanResultService;

/**
 * Controller for handling viewing reports for a given upload scan
 *
 * @author csmith
 */
@Controller
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "')")
public class PullRequestReportController {
	private PRScanResultService scanResultService;

	public PullRequestReportController(@Autowired PRScanResultService scanResultService) {
		this.scanResultService = scanResultService;
	}

	@GetMapping("/scan/report/{id}")
	public WatchtowerModelAndView getUploadReport(@PathVariable String id,
			RedirectAttributes redirectAttributes) {
		WatchtowerModelAndView mav = new WatchtowerModelAndView("pull_requests/scanreport");
		PRScanResult scanResult = scanResultService.getScanResultForScanId(id);
		if (scanResult == null) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Unknown ID");
			mav.setViewName("redirect:/scan");
		} else {
			mav.addObject("result", scanResult);
			mav.addScriptReference("/scripts/scan_report.js");
		}
		return mav;
	}

}
