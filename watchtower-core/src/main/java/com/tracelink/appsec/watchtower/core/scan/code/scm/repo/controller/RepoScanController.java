package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.controller;

import java.security.Principal;
import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Page;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.util.UriComponentsBuilder;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.PagedResult;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetChoices;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetPageService;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanResultsService;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.RepoScanService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.RepoScanService.PlanRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.RepoScanSettingsService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.QueueJobView;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.RepoScanViewService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.PlanFrequency;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanPlanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.plan.RepoSelector;

/**
 * The repository scan page: runs, recurring plans and the work queue, as segments of one page,
 * and the scan dialog's submit. Repositories themselves are managed in the inventory
 * ({@code /repository/pull_request}). Every action returns at once; the queue does the slow
 * work.
 *
 * @author Watchtower
 */
@Controller
@RequestMapping("/reposcan")
public class RepoScanController {

	private static final String REDIRECT = "redirect:/reposcan";

	private static final String INVENTORY = "/repositories";

	private final RepoScanViewService views;

	private final RepoScanService scans;

	private final RepoScanSettingsService settings;

	private final RulesetPageService rulesets;

	private final CodeScanResultsService results;

	public RepoScanController(RepoScanViewService views, RepoScanService scans,
			RepoScanSettingsService settings, RulesetPageService rulesets,
			CodeScanResultsService results) {
		this.views = views;
		this.scans = scans;
		this.settings = settings;
		this.rulesets = rulesets;
		this.results = results;
	}

	@GetMapping
	@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "')")
	public WatchtowerModelAndView page(@RequestParam(defaultValue = "runs") String view,
			@RequestParam Optional<String> source, @RequestParam(defaultValue = "") String q,
			@RequestParam(defaultValue = "0") int page,
			@RequestParam(defaultValue = "all") String jobs,
			@RequestParam(name = "new", defaultValue = "false") boolean newScan) {
		if ("runs".equals(view)) {
			WatchtowerModelAndView moved = new WatchtowerModelAndView("repo_scan/index");
			moved.setViewName("redirect:/scans/results?type=repository");
			return moved;
		}
		if ("repositories".equals(view)) {
			// Repositories moved to the inventory; old links keep their integration and search
			WatchtowerModelAndView moved = new WatchtowerModelAndView("repo_scan/index");
			moved.getModelMap().clear();
			UriComponentsBuilder url = UriComponentsBuilder.fromPath(INVENTORY);
			source.ifPresent(s -> url.queryParam("source", s));
			if (!q.isBlank()) {
				url.queryParam("q", q.trim());
			}
			moved.setViewName("redirect:" + url.encode().build().toUriString());
			return moved;
		}
		WatchtowerModelAndView mv = new WatchtowerModelAndView("repo_scan/index");
		String active = switch (view) {
			case "plans", "queue" -> view;
			default -> "runs";
		};
		mv.addObject("view", active);
		mv.addObject("openNewScan", newScan);
		mv.addObject("paused", settings.isPaused());
		mv.addObject("queuedCount", views.countScans(ScanStatus.NOT_STARTED));
		mv.addObject("runningCount", views.countScans(ScanStatus.IN_PROGRESS));
		mv.addObject("runsCount", views.countRuns());
		mv.addObject("plansCount", views.countPlans());
		// Plans and Queue are tabs of Repository results (Fixes board 2026-10-22): same tab counts.
		mv.addObject("resultCounts", results.counts(null));
		switch (active) {
			case "plans" -> addPage(mv, "plans", views.recurringPlans(page),
					"/reposcan?view=plans");
			case "queue" -> {
				mv.addObject("repositoryAdmissionBlocker", views.repositoryAdmissionBlocker());
				List<RepoScanEntity> queued = views.queuedScans();
				mv.addObject("queuedScans", queued);
				mv.addObject("queuePlans", views.plansOf(queued));
				mv.addObject("activeJobs", views.activeJobs());
				QueueJobView.Filter jobFilter = QueueJobView.Filter.of(jobs);
				mv.addObject("jobFilter", jobFilter);
				mv.addObject("jobFilters", QueueJobView.Filter.values());
				mv.addObject("recentJobs", views.recentJobs(jobFilter));
			}
			default -> {
				Page<RepoScanViewService.RunSummary> runs = views.recentRuns(page);
				addPage(mv, "runs", runs, "/reposcan?view=runs");
				mv.addObject("runOverviews", views.runOverviews(runs.getContent()));
			}
		}
		// The New scan dialog: pick an integration and repositories by selector
		mv.addObject("integrations", views.scmIntegrations());
		mv.addObject("rulesetChoices", RulesetChoices.of(rulesets.summaries()));
		mv.addObject("frequencies", PlanFrequency.values());
		mv.addScriptReference("/scripts/repo-scan.js");
		mv.addScriptReference("/scripts/ruleset-picker.js");
		return mv;
	}

	private static <T> void addPage(WatchtowerModelAndView mv, String name, Page<T> page,
			String baseUrl) {
		mv.addObject(name, page.getContent());
		mv.addObject("pagination", PagedResult.of(page, r -> r));
		mv.addObject("baseUrl", baseUrl);
	}

	/**
	 * Scans the chosen repositories now, or saves a recurring plan. Repositories come either as
	 * ids (selected in the inventory) or as a selector (names, globs, label:, team:, project:,
	 * or *), as typed in the New scan dialog.
	 */
	@PostMapping("/submit")
	@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_SUBMIT_NAME + "')")
	public String submit(@RequestParam String apiLabel,
			@RequestParam(required = false) List<Long> repoIds,
			@RequestParam(defaultValue = "") String selector,
			@RequestParam(defaultValue = "") String branches,
			@RequestParam(required = false) Long rulesetId,
			@RequestParam(defaultValue = "ONCE") String frequency,
			@RequestParam(required = false) Integer hour,
			@RequestParam(required = false) Integer day,
			@RequestParam(required = false) Integer skipStaleDays,
			@RequestParam(defaultValue = "") String name, Principal user,
			RedirectAttributes redirect) {
		boolean fromInventory = repoIds != null && !repoIds.isEmpty();
		try {
			String repoSelector = fromInventory ? RepoSelector.ofIds(repoIds) : selector;
			PlanFrequency when = PlanFrequency.valueOf(frequency);
			RepoScanPlanEntity plan = scans.submit(new PlanRequest(name, apiLabel, repoSelector,
					branches, rulesetId == null || rulesetId < 0 ? null : rulesetId, when, hour,
					day, skipStaleDays), user.getName());
			if (when.isRecurring()) {
				redirect.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						"Saved plan " + plan.getName());
				return REDIRECT + "?view=plans";
			}
			return "redirect:/reposcan/run/" + plan.getId() + "/1";
		} catch (IllegalArgumentException e) {
			redirect.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
			if (!fromInventory) {
				// Straight to a page that shows it: plain /reposcan redirects again and the message is lost
				return REDIRECT + "?view=queue";
			}
			// Back to the integration's tab only by its stored name, never the request's text
			views.scmIntegrations().stream().filter(apiLabel::equals).findFirst()
					.ifPresent(known -> redirect.addAttribute("source", known));
			return "redirect:" + INVENTORY;
		}
	}

	@PostMapping("/pause")
	@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_ADMIN_NAME + "')")
	public String pause(@RequestParam boolean paused,
			@RequestParam(defaultValue = "queue") String view, Principal user,
			RedirectAttributes redirect) {
		settings.setPaused(paused, user.getName());
		redirect.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
				paused ? "Repository scans paused" : "Repository scans resumed");
		// Back to the tab it was pressed on (the button is on every tab); only known tabs.
		if ("results".equals(view)) {
			return "redirect:/scans/results";
		}
		String back = switch (view) {
			case "runs", "plans" -> view;
			default -> "queue";
		};
		return REDIRECT + "?view=" + back;
	}

	@PostMapping("/plans/{id}/run")
	@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_SUBMIT_NAME + "')")
	public String runPlan(@PathVariable long id, Principal user, RedirectAttributes redirect) {
		try {
			scans.runNow(id, user.getName());
			redirect.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Run started");
		} catch (IllegalArgumentException e) {
			redirect.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
		}
		return REDIRECT + "?view=runs";
	}

	@PostMapping("/plans/{id}/enabled")
	@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_SUBMIT_NAME + "')")
	public String enablePlan(@PathVariable long id, @RequestParam boolean enabled,
			RedirectAttributes redirect) {
		try {
			scans.setEnabled(id, enabled);
		} catch (IllegalArgumentException e) {
			redirect.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
		}
		return REDIRECT + "?view=plans";
	}

	@PostMapping("/plans/{id}/delete")
	@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_SUBMIT_NAME + "')")
	public String deletePlan(@PathVariable long id, Principal user,
			RedirectAttributes redirect) {
		scans.delete(id, user.getName());
		redirect.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION, "Plan deleted");
		return REDIRECT + "?view=plans";
	}
}
