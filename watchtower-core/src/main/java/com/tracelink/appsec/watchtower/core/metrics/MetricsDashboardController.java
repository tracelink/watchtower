package com.tracelink.appsec.watchtower.core.metrics;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.data.util.Pair;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.workflow.RuleWorkService;
import com.tracelink.appsec.watchtower.core.scan.ScanType;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanType;
import com.tracelink.appsec.watchtower.core.scan.queue.PRScanWorkloadService;

/**
 * Controller for the dashboard and home page of Watchtower
 *
 * @author csmith
 */
@Controller
@RequestMapping("/")
@PreAuthorize("isAuthenticated()")
public class MetricsDashboardController {

	private static final Logger LOG = LoggerFactory.getLogger(MetricsDashboardController.class);
	/** Home counts rule work over the same default window as the Rule work page. */
	private static final int WORK_WINDOW_DAYS = 30;

	private MetricsCacheService metricsService;
	private final HomeDashboardService homeDashboardService;
	private final PRScanWorkloadService scanWorkloadService;
	private final RuleWorkService ruleWork;
	private List<ScanType> scanMetrics = new ArrayList<>();

	public MetricsDashboardController(@Autowired MetricsCacheService metricsService,
			HomeDashboardService homeDashboardService,
			PRScanWorkloadService scanWorkloadService, RuleWorkService ruleWork) {
		this.metricsService = metricsService;
		this.homeDashboardService = homeDashboardService;
		this.scanWorkloadService = scanWorkloadService;
		this.ruleWork = ruleWork;
		this.scanMetrics.addAll(Arrays.asList(CodeScanType.values()));
		this.scanMetrics.addAll(Arrays.asList(ImageScanType.values()));
	}

	@GetMapping
	public WatchtowerModelAndView dashboard(Authentication viewer) {
		WatchtowerModelAndView mv = new WatchtowerModelAndView("metricsdashboard")
				.addScriptReference("/scripts/home-digest.js");

		if (!metricsService.isMetricsCacheReady()) {
			mv.addObject("metricsStale", true);
		}
		mv.addObject("metrics", makeTopLevelMetrics());
		mv.addObject("homeTotals", homeTotals());
		mv.addObject("workTiles", workTiles(viewer));
		mv.addObject("overview", homeDashboardService.getOverview());
		mv.addObject("recentActivity", homeDashboardService.getRecentActivity());
		mv.addObject("processorHealth", homeDashboardService.getProcessorHealth());
		mv.addObject("scanWorkload", scanWorkloadService.getWorkload());
		mv.addObject("metricDescriptions", Map.of(
				"Scans Completed", "Total completed scans recorded for this scan type.",
				"Violations Found", "Non-informational findings across completed scans.",
				"Average Scan Time", "Mean elapsed time from scan start to completion.",
				"Scans Today", "Completed scans since midnight UTC.",
				"Avg Repo Size", "Mean source size for pull-request scans with size data."));

		return mv;
	}

	@GetMapping("scan-workload")
	public String scanWorkload(Model model,
			@RequestParam(defaultValue = "card") String part) {
		model.addAttribute("scanWorkload", scanWorkloadService.getWorkload());
		// Only two fixed fragments; any other value gets the card.
		return "chip".equals(part) ? "fragments/scanworkload :: chip" : "fragments/scanworkload :: workload";
	}

	/**
	 * Removes one pull request scan request that failed validation from the workload list. Goes back
	 * to the page the button was on, never to an address from the request.
	 */
	@PostMapping("scan-workload/{id}/dismiss")
	@PreAuthorize("hasAuthority('" + CorePrivilege.PR_SETTINGS_MODIFY_NAME + "')")
	public String dismissFailedScan(@PathVariable long id,
			@RequestHeader(value = "Referer", required = false) String referer, Principal user,
			RedirectAttributes redirect) {
		try {
			scanWorkloadService.dismissFailed(id);
			LOG.info("{} removed failed pull request scan request {} from the list", user.getName(),
					id);
			redirect.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Removed the failed request from the list.");
		} catch (IllegalArgumentException e) {
			redirect.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION, e.getMessage());
		}
		return "redirect:" + workloadPageFor(referer);
	}

	/** The page that shows the workload card besides Home; anything else goes Home. */
	static String workloadPageFor(String referer) {
		if (referer == null) {
			return "/";
		}
		try {
			String path = java.net.URI.create(referer).getPath();
			return "/scan/dashboard".equals(path) ? path : "/";
		} catch (IllegalArgumentException e) {
			return "/";
		}
	}

	/** All-time totals per scan type, each row offering the same Dashboard · Results · New scan. */
	private List<HomeTotal> homeTotals() {
		return List.of(
				total("Pull requests", "compare_arrows", CodeScanType.PULL_REQUEST, "/scan/dashboard",
						"/scan/results/all", "/scan"),
				total("Uploads", "backup", CodeScanType.UPLOAD, "/uploadscan/dashboard",
						"/uploadscan/results", "/uploadscan"),
				total("Repositories", "code", CodeScanType.REPOSITORY, "/reposcan/dashboard",
						"/scans/results?type=repository", "/reposcan?view=plans&new=true"),
				total("Images", "developer_board", ImageScanType.CONTAINER, "/imagescan/dashboard",
						"/imagescan/results", null));
	}

	private HomeTotal total(String label, String icon, ScanType type, String dashboard,
			String results, String newScan) {
		return new HomeTotal(label, icon, metricsService.getScanCount(type),
				metricsService.getViolationCount(type), dashboard, results, newScan);
	}

	/**
	 * Rule work queue counts for people who may open Rule work; empty otherwise. Home must render
	 * even if a count query fails, so a failure is logged and the strip is omitted.
	 */
	private List<HomeWorkTile> workTiles(Authentication viewer) {
		boolean canModify = has(viewer, CorePrivilege.RULE_MODIFY_NAME);
		if (viewer == null || !(canModify || has(viewer, CorePrivilege.RULESETS_VIEW_NAME))) {
			return List.of();
		}
		try {
			var filter = new RuleWorkService.Filter("", "", false, WORK_WINDOW_DAYS, "all",
					has(viewer, CorePrivilege.SCAN_RESULTS_NAME), canModify);
			return HomeWorkTile.from(ruleWork.counts(filter, null, 0));
		} catch (RuntimeException failure) {
			LOG.warn("Could not count rule work for the home page", failure);
			return List.of();
		}
	}

	private static boolean has(Authentication viewer, String privilege) {
		return viewer != null && viewer.getAuthorities().stream()
				.anyMatch(authority -> privilege.equals(authority.getAuthority()));
	}

	private Map<String, Object> makeTopLevelMetrics() {
		Map<String, Object> topLevelMetrics = new LinkedHashMap<>();
		for (ScanType type : this.scanMetrics) {
			List<Pair<String, String>> stats = new ArrayList<>(Arrays.asList(
					Pair.of("Scans Completed",
							String.valueOf(metricsService.getScanCount(type))),
					Pair.of("Violations Found",
							String.valueOf(metricsService.getViolationCount(type))),
					Pair.of("Average Scan Time",
							metricsService.getAverageScanTimeString(type)),
					Pair.of("Scans Today",
							String.valueOf(metricsService.getScanCountToday(type)))));
			// PR scans only - upload and image scans have no BB repo context (item 6.5).
			if (CodeScanType.PULL_REQUEST.equals(type)) {
				stats.add(Pair.of("Avg Repo Size", metricsService.getAverageSourceSizeString(type)));
			}
			topLevelMetrics.put(type.getDisplayName(), stats);
		}
		return topLevelMetrics;
	}

}
