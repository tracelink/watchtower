package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.metrics.MetricsCacheService;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.scan.presentation.HomeActivityItem;
import com.tracelink.appsec.watchtower.core.scan.queue.PRScanWorkloadService;

/**
 * Controller for the dashboard and home page of Watchtower
 *
 * @author csmith
 */
@Controller
@RequestMapping("/scan/dashboard")
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_DASHBOARDS_NAME + "')")
public class PRDashboardController {

	private PRScanResultService prScanResultService;

	private MetricsCacheService metricsService;
	private final PRScanWorkloadService scanWorkloadService;

	public PRDashboardController(@Autowired PRScanResultService prScanResultService,
			@Autowired MetricsCacheService metricsService,
			PRScanWorkloadService scanWorkloadService) {
		this.prScanResultService = prScanResultService;
		this.metricsService = metricsService;
		this.scanWorkloadService = scanWorkloadService;
	}

	/**
	 * Gets the dashboard page with loaded values for totals blocks and the unresolved pull requests
	 * list.
	 *
	 * @return model and view object for the dashboard page
	 */
	@GetMapping
	public WatchtowerModelAndView dashboard() {
		WatchtowerModelAndView mv = new WatchtowerModelAndView("pull_requests/dashboard");

		mv.addObject("metricsReady", metricsService.isMetricsCacheReady());
		mv.addObject("numScans",
				metricsService.getScanCount(CodeScanType.PULL_REQUEST));
		mv.addObject("numViolations",
				metricsService.getViolationCount(CodeScanType.PULL_REQUEST));
		mv.addObject("numPrs", metricsService.getPullRequestCount());
		mv.addObject("numRepos", metricsService.getRepositoryCount());
		mv.addObject("avgScanTime",
				metricsService.getAverageScanTimeString(CodeScanType.PULL_REQUEST));
		mv.addObject("recentScans", prScanResultService.getLastScans(5).stream()
				.map(HomeActivityItem::fromPullRequest).toList());
		mv.addObject("scanWorkload", scanWorkloadService.getWorkload());

		mv.addScriptReference("/webjars/chart.js/4.4.0/dist/chart.umd.js");
		mv.addScriptReference("/scripts/dashboard/utils.js");
		mv.addScriptReference("/scripts/dashboard/dashboard-stats-switcher.js");
		mv.addScriptReference("/scripts/dashboard/dashboard-insights.js");
		mv.addScriptReference("/scripts/dashboard/pr-dashboard.js");
		return mv;
	}

}
