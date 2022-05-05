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

	public PRDashboardController(@Autowired PRScanResultService prScanResultService,
			@Autowired MetricsCacheService metricsService) {
		this.prScanResultService = prScanResultService;
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
		WatchtowerModelAndView mv = new WatchtowerModelAndView("pull_requests/dashboard");

		if (!metricsService.isMetricsCacheReady()) {
			mv.addObject(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					MetricsCacheService.METRICS_NOT_READY);
		}
		mv.addObject("numScans",
				metricsService.getScanCount(CodeScanType.PULL_REQUEST));
		mv.addObject("numViolations",
				metricsService.getViolationCount(CodeScanType.PULL_REQUEST));
		mv.addObject("numPrs", prScanResultService.countPrs());
		mv.addObject("numRepos", prScanResultService.countRepos());

		mv.addScriptReference("/scripts/dashboard/utils.js");
		mv.addScriptReference("/scripts/dashboard/dashboard-stats-switcher.js");
		mv.addScriptReference("/scripts/dashboard/scans-vios-line.js");
		mv.addScriptReference("/scripts/dashboard/violations-pie.js");
		mv.addScriptReference("/scripts/dashboard/violations-bar.js");
		mv.addScriptReference("/scripts/dashboard/pr-dashboard.js");
		return mv;
	}

}
