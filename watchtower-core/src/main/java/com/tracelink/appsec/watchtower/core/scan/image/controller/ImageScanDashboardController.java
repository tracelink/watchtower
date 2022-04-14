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

@Controller
@RequestMapping("/imagescan/dashboard")
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_DASHBOARDS_NAME + "')")
public class ImageScanDashboardController {

	private MetricsCacheService metricsService;

	public ImageScanDashboardController(@Autowired MetricsCacheService metricsService) {
		this.metricsService = metricsService;
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

		if (!metricsService.isMetricsCacheReady()) {
			mv.addObject(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					MetricsCacheService.METRICS_NOT_READY);
		}

		mv.addObject("numScans",
				metricsService.getScanCount(ImageScanType.CONTAINER));
		mv.addObject("numViolations",
				metricsService.getViolationCount(ImageScanType.CONTAINER));
		mv.addObject("avgScanTime",
				metricsService.getAverageScanTimeString(ImageScanType.CONTAINER));

		mv.addScriptReference("/scripts/dashboard/utils.js");
		mv.addScriptReference("/scripts/dashboard/scans-vios-line.js");
		mv.addScriptReference("/scripts/dashboard/violations-pie.js");
		mv.addScriptReference("/scripts/dashboard/violations-bar.js");
		mv.addScriptReference("/scripts/dashboard/image-dashboard.js");
		return mv;
	}
}
