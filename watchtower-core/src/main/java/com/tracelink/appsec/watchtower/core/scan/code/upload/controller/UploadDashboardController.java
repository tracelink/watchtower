package com.tracelink.appsec.watchtower.core.scan.code.upload.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.metrics.MetricsCacheService;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.upload.service.UploadScanResultService;
import com.tracelink.appsec.watchtower.core.scan.presentation.HomeActivityItem;

/**
 * Controller for the dashboard and home page of Watchtower
 *
 * @author csmith
 */
@Controller
@RequestMapping("/uploadscan/dashboard")
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_DASHBOARDS_NAME + "')")
public class UploadDashboardController {
	private MetricsCacheService metricsService;
	private UploadScanResultService scanResultService;

	public UploadDashboardController(@Autowired MetricsCacheService metricsService,
			@Autowired UploadScanResultService scanResultService) {
		this.metricsService = metricsService;
		this.scanResultService = scanResultService;
	}

	/**
	 * Gets the dashboard page with loaded values for totals blocks and the unresolved pull requests
	 * list.
	 *
	 * @return model and view object for the dashboard page
	 */
	@GetMapping
	public WatchtowerModelAndView dashboard() {
		WatchtowerModelAndView mv = new WatchtowerModelAndView("upload_scan/dashboard");

		mv.addObject("metricsReady", metricsService.isMetricsCacheReady());

		mv.addObject("numScans",
				metricsService.getScanCount(CodeScanType.UPLOAD));
		mv.addObject("numViolations",
				metricsService.getViolationCount(CodeScanType.UPLOAD));
		mv.addObject("avgScanTime", metricsService.getAverageScanTimeString(CodeScanType.UPLOAD));
		mv.addObject("recentScans", scanResultService.getLastScans(5).stream()
				.map(HomeActivityItem::fromUpload).toList());

		mv.addScriptReference("/webjars/chart.js/4.4.0/dist/chart.umd.js");
		mv.addScriptReference("/scripts/dashboard/utils.js");
		mv.addScriptReference("/scripts/dashboard/dashboard-stats-switcher.js");
		mv.addScriptReference("/scripts/dashboard/dashboard-insights.js");
		mv.addScriptReference("/scripts/dashboard/upload-dashboard.js");
		return mv;
	}

}
