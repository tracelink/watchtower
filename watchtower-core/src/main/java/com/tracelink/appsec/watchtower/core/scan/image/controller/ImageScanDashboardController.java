package com.tracelink.appsec.watchtower.core.scan.image.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.metrics.MetricsCacheService;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanType;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageScanResultService;
import com.tracelink.appsec.watchtower.core.scan.presentation.HomeActivityItem;

/**
 * Controller for the main Image Scan Dashboard
 * 
 * @author csmith
 *
 */
@Controller
@RequestMapping("/imagescan/dashboard")
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_DASHBOARDS_NAME + "')")
public class ImageScanDashboardController {

	private MetricsCacheService metricsService;
	private ImageScanResultService scanResultService;

	public ImageScanDashboardController(@Autowired MetricsCacheService metricsService,
			@Autowired ImageScanResultService scanResultService) {
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
		WatchtowerModelAndView mv = new WatchtowerModelAndView("image_scan/dashboard");

		mv.addObject("metricsReady", metricsService.isMetricsCacheReady());

		mv.addObject("numScans",
				metricsService.getScanCount(ImageScanType.CONTAINER));
		mv.addObject("numViolations",
				metricsService.getViolationCount(ImageScanType.CONTAINER));
		mv.addObject("avgScanTime",
				metricsService.getAverageScanTimeString(ImageScanType.CONTAINER));
		mv.addObject("recentScans", scanResultService.getLastScans(5).stream()
				.map(HomeActivityItem::fromImage).toList());

		mv.addScriptReference("/webjars/chart.js/4.4.0/dist/chart.umd.js");
		mv.addScriptReference("/scripts/dashboard/utils.js");
		mv.addScriptReference("/scripts/dashboard/dashboard-stats-switcher.js");
		mv.addScriptReference("/scripts/dashboard/dashboard-insights.js");
		mv.addScriptReference("/scripts/dashboard/image-dashboard.js");
		return mv;
	}
}
