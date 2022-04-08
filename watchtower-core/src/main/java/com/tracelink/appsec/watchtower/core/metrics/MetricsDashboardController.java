package com.tracelink.appsec.watchtower.core.metrics;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.util.Pair;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.ScanType;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanType;

/**
 * Controller for the dashboard and home page of Watchtower
 *
 * @author csmith
 */
@Controller
@RequestMapping("/")
@PreAuthorize("isAuthenticated()")
public class MetricsDashboardController {

	private MetricsCacheService metricsService;
	private List<ScanType> scanMetrics = new ArrayList<>();

	public MetricsDashboardController(@Autowired MetricsCacheService metricsService) {
		this.metricsService = metricsService;
		this.scanMetrics.addAll(Arrays.asList(CodeScanType.values()));
		this.scanMetrics.addAll(Arrays.asList(ImageScanType.values()));
	}

	@GetMapping
	public WatchtowerModelAndView dashboard() {
		WatchtowerModelAndView mv = new WatchtowerModelAndView("metricsdashboard");

		if (!metricsService.isMetricsCacheReady()) {
			mv.addObject(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					MetricsCacheService.METRICS_NOT_READY);
		}
		mv.addObject("metrics", makeTopLevelMetrics());

		return mv;
	}

	private Map<String, Object> makeTopLevelMetrics() {
		Map<String, Object> topLevelMetrics = new LinkedHashMap<>();
		for (ScanType type : this.scanMetrics) {
			topLevelMetrics.put(type.getDisplayName(),
					Arrays.asList(
							Pair.of("Scans Completed",
									String.valueOf(metricsService.getScanCount(type))),
							Pair.of("Violations Found",
									String.valueOf(metricsService.getViolationCount(type))),
							Pair.of("Average Scan Time",
									metricsService.getAverageScanTimeString(type))));
		}
		return topLevelMetrics;
	}

}
