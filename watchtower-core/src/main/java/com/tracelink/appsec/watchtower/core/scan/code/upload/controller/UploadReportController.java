package com.tracelink.appsec.watchtower.core.scan.code.upload.controller;

import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.feedback.FindingFeedbackService;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.service.UploadScanResultService;
import com.tracelink.appsec.watchtower.core.scan.code.upload.result.UploadScanResult;
import com.tracelink.appsec.watchtower.core.scan.presentation.FindingPresentationModel;

/**
 * Controller for handling viewing reports for a given upload scan
 *
 * @author csmith
 */
@Controller
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "')")
public class UploadReportController {
	private static final Logger LOG = LoggerFactory.getLogger(UploadReportController.class);

	private UploadScanResultService scanResultService;

	@Autowired(required = false)
	private FindingFeedbackService feedbackService;

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
			UploadScanResult result = scanResultService.generateResultForTicket(ticket);
			mav.addObject("result", result);
   mav.addObject("feedbackScanId",scanEntity.getLatestUploadScan()==null?null:scanEntity.getLatestUploadScan().getId());
			List<FindingPresentationModel> findings =
					FindingPresentationModel.fromUpload(result.getViolations());
			if (scanEntity.getLatestUploadScan() != null) {
				markReviewed(findings, scanEntity.getLatestUploadScan().getId());
			}
			mav.addObject("findings", findings);
			mav.addScriptReference("/scripts/scan_report.js");
			mav.addScriptReference("/scripts/workspace-resizer.js");
			mav.addScriptReference("/scripts/finding-workspace.js");
		}
		return mav;
	}

	/** Marks each finding with its latest human judgment; a failure only drops the markers. */
	private void markReviewed(List<FindingPresentationModel> findings, long scanId) {
		if (feedbackService == null || findings.isEmpty()) {
			return;
		}
		try {
			Map<String, String> judgments = feedbackService.judgmentsByKey("upload", scanId);
			findings.forEach(finding -> finding.withReview(
					finding.getFeedbackKey() == null ? null : judgments.get(finding.getFeedbackKey())));
		} catch (RuntimeException e) {
			LOG.warn("Could not load review markers for upload scan {}", scanId, e);
		}
	}
}
