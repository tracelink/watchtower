package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.metrics.MetricsCacheService;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.RepoScanViewService;
import com.tracelink.appsec.watchtower.core.scan.presentation.HomeActivityItem;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryInventoryService;

/**
 * The repository scan dashboard: coverage (how many repositories still in the SCM a repository
 * scan reached in the last 30 days), then the same activity charts, date-range switch and
 * findings by rule as the other scan types, from the metrics projections the scan runner
 * writes, and the latest finished scans.
 *
 * @author Watchtower
 */
@Controller
@RequestMapping("/reposcan/dashboard")
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_DASHBOARDS_NAME + "')")
public class RepoScanDashboardController {

	static final int RECENT_SCANS = 5;

	private final MetricsCacheService metricsService;

	private final RepoScanViewService views;

	private final RepositoryInventoryService inventory;

	public RepoScanDashboardController(MetricsCacheService metricsService,
			RepoScanViewService views, RepositoryInventoryService inventory) {
		this.metricsService = metricsService;
		this.views = views;
		this.inventory = inventory;
	}

	@GetMapping
	public WatchtowerModelAndView dashboard() {
		WatchtowerModelAndView mv = new WatchtowerModelAndView("repo_scan/dashboard");
		mv.addObject("metricsReady", metricsService.isMetricsCacheReady());
		mv.addObject("numScans", metricsService.getScanCount(CodeScanType.REPOSITORY));
		mv.addObject("numViolations", metricsService.getViolationCount(CodeScanType.REPOSITORY));
		mv.addObject("avgScanTime",
				metricsService.getAverageScanTimeString(CodeScanType.REPOSITORY));
		mv.addObject("coverage", inventory.coverage(CodeScanType.PULL_REQUEST));
		mv.addObject("recentScans", views.latestFinished(RECENT_SCANS).stream()
				.map(HomeActivityItem::fromRepo).toList());

		mv.addScriptReference("/webjars/chart.js/4.4.0/dist/chart.umd.js");
		mv.addScriptReference("/scripts/dashboard/utils.js");
		mv.addScriptReference("/scripts/dashboard/dashboard-stats-switcher.js");
		mv.addScriptReference("/scripts/dashboard/dashboard-insights.js");
		mv.addScriptReference("/scripts/dashboard/repo-dashboard.js");
		return mv;
	}
}
