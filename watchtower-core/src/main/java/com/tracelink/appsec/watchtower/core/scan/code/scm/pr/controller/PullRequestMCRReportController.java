package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.controller;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestMCRStatus;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResult;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResultViolation;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Arrays;
import java.util.List;

/**
 * Controller for handling viewing reports for a given Pull Request Manual Code Review
 *
 * @author droseen
 */

@Controller
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "')")
public class PullRequestMCRReportController {
	private final PRScanResultService scanResultService;

	private final List<PullRequestMCRStatus> allowedStatuses =
			Arrays.asList(PullRequestMCRStatus.NOT_APPLICABLE, PullRequestMCRStatus.PENDING_REVIEW, PullRequestMCRStatus.IN_PROGRESS, PullRequestMCRStatus.REVIEWED, PullRequestMCRStatus.RECOMMENDATIONS);

	public PullRequestMCRReportController(@Autowired PRScanResultService scanResultService) {
		this.scanResultService = scanResultService;
	}

	@RequestMapping(method=RequestMethod.GET, value="/scan/mcr/report/{id}")
	public WatchtowerModelAndView getPRReport(@PathVariable String id,
			RedirectAttributes redirectAttributes) {
		WatchtowerModelAndView mav = new WatchtowerModelAndView("pull_requests/mcrreport");
		PRScanResult scanResult = scanResultService.getScanResultForScanId(id);
		List<PRScanResultViolation> mcrFindings = scanResult.getMcrFindings();
		if (scanResult == null) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Unknown ID");
			mav.setViewName("redirect:/scan/mcr/");
		} else {
			mav.addObject("result", scanResult);
			mav.addObject("mcrFindings", mcrFindings);
			mav.addScriptReference("/scripts/scan_report.js");
		}
		mav.addObject("mcrStatuses", PullRequestMCRStatus.values());
		mav.addObject("currentMcrStatus", scanResult.getMcrStatus());
		return mav;
	}

	@RequestMapping(method=RequestMethod.POST, value="/scan/mcr/report/{id}/setstatus")
	@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_MCR_MODIFY_NAME + "')")
	public String setReportsMcrStatus(@RequestParam("mcrstatus") String mcrStatus, @PathVariable Long id) {
		PullRequestMCRStatus status = PullRequestMCRStatus.enumStringToStatus(mcrStatus);
		if (allowedStatuses.contains(status)) {
			scanResultService.updateMcrStatus(id, status);
		}
		return "redirect:/scan/mcr/report/" + id;
	}

}
