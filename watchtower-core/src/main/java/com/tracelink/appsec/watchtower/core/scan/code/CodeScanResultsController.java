package com.tracelink.appsec.watchtower.core.scan.code;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanResultsService.Kind;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.RepoScanSettingsService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.RepoScanViewService;

/**
 * One results destination for PR and full-repository scans. Its tabs (All, Pull requests, Full
 * repository, Plans, Queue) and scanner state are shared with the repository scan page.
 */
@Controller
@RequestMapping("/scans/results")
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "')")
public class CodeScanResultsController {
	private final CodeScanResultsService results;
	private final RepoScanViewService views;
	private final RepoScanSettingsService settings;

	public CodeScanResultsController(CodeScanResultsService results, RepoScanViewService views,
			RepoScanSettingsService settings) {
		this.results = results;
		this.views = views;
		this.settings = settings;
	}

	@GetMapping
	public WatchtowerModelAndView page(@RequestParam(defaultValue = "all") String type,
			@RequestParam(defaultValue = "0") int page) {
		Kind kind = Kind.of(type);
		WatchtowerModelAndView mv = new WatchtowerModelAndView("code_scan/results");
		mv.addObject("kind", kind);
		mv.addObject("kinds", Kind.values());
		var paged = results.page(kind, page, null);
		mv.addObject("results", paged.content());
		mv.addObject("pagination", paged);
		mv.addObject("baseUrl", "/scans/results?type=" + kind.getKey());
		mv.addObject("resultCounts", results.counts(null));
		mv.addObject("paused", settings.isPaused());
		mv.addObject("queuedCount", views.countScans(ScanStatus.NOT_STARTED));
		mv.addObject("runningCount", views.countScans(ScanStatus.IN_PROGRESS));
		mv.addObject("plansCount", views.countPlans());
		return mv;
	}
}
