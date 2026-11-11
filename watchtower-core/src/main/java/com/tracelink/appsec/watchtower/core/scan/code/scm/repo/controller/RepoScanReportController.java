package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.controller;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.RepoScanViewService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanPlanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanExporter;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReportService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanPlanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;

/**
 * A run of a plan (one row per repository and branch) and the report of one scan, with exports.
 *
 * @author Watchtower
 */
@Controller
@RequestMapping("/reposcan")
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_RESULTS_NAME + "')")
public class RepoScanReportController {
	@org.springframework.beans.factory.annotation.Autowired(required = false)
	private com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService remoteAssessments;

    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private com.tracelink.appsec.watchtower.core.scan.code.report.ScanReportExporter combinedExports;
	private final RepoScanRepository scans;

	private final RepoScanPlanRepository plans;

	private final RepoScanReportService reports;

	public RepoScanReportController(RepoScanRepository scans, RepoScanPlanRepository plans,
			RepoScanReportService reports) {
		this.scans = scans;
		this.plans = plans;
		this.reports = reports;
	}

	@org.springframework.beans.factory.annotation.Autowired(required = false)
	private com.tracelink.appsec.watchtower.core.job.AsyncJobRepository jobs;

	/**
	 * Why a run has no scans: preparation still going, finished having found nothing to scan, or
	 * failed. A run with no rows used to read "Preparing this run…" for ever, including when the
	 * selection matched no repository.
	 *
	 * @return null while preparation may still be working, otherwise a plain sentence
	 */
	private String emptyRunReason(long planId, int runNo) {
		if (jobs == null) {
			return null;
		}
		var job = jobs.findFirstByTypeAndPayloadOrderByIdDesc(
				com.tracelink.appsec.watchtower.core.job.AsyncJobType.EXPAND_PLAN,
				com.tracelink.appsec.watchtower.core.scan.code.scm.repo.plan.ExpandPlanHandler
						.payload(planId, runNo));
		if (job == null || !job.getStatus().isFinished()) {
			return null;
		}
		return job.getStatus() == com.tracelink.appsec.watchtower.core.job.AsyncJobStatus.FAILED
				? "Preparing this run failed, so nothing was scanned. See Recent background jobs on the Queue tab."
				: "Nothing matched this run's selection (repositories, labels or branches), so nothing was scanned.";
	}

	@GetMapping("/run/{planId}/{runNo}")
	public WatchtowerModelAndView run(@PathVariable long planId, @PathVariable int runNo) {
		RepoScanPlanEntity plan = plans.findById(planId)
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
		List<RepoScanEntity> rows = scans.findRun(planId, runNo);
		WatchtowerModelAndView mv = new WatchtowerModelAndView("repo_scan/run");
		mv.addObject("plan", plan);
		mv.addObject("runNo", runNo);
		mv.addObject("rows", rows);
		mv.addObject("emptyReason", rows.isEmpty() ? emptyRunReason(planId, runNo) : null);
		// The run's status (its worst repository) for the chip beside the title.
		mv.addObject("overview", com.tracelink.appsec.watchtower.core.scan.code.scm.repo.RunOverview.of(null, rows));
		mv.addObject("totalFindings", rows.stream().mapToInt(RepoScanEntity::getCombinedFindingCount)
				.sum());
		mv.addObject("newFindings", rows.stream()
				.mapToInt(r -> r.getNewCount() == null ? 0 : r.getNewCount()).sum());
		mv.addObject("finished", rows.stream().filter(r -> r.getEndDate() > 0).count());
		mv.addObject("failed", rows.stream().filter(r -> r.getStatus() == ScanStatus.FAILED)
				.count());
		return mv;
	}

	private static final java.util.Set<String> REPORT_VIEWS = java.util.Set.of("findings", "byrule", "fixed");
	private static final int REPORT_VIEW_PAGE_SIZE = 25;

	@GetMapping("/report/{scanId}")
	public WatchtowerModelAndView report(@PathVariable long scanId,
			@org.springframework.web.bind.annotation.RequestParam(defaultValue = "findings") String view,
			@org.springframework.web.bind.annotation.RequestParam(defaultValue = "") String search,
			@org.springframework.web.bind.annotation.RequestParam(defaultValue = "0") int page) {
		if (!REPORT_VIEWS.contains(view) || page < 0 || search.length() > 200) {
			throw new org.springframework.web.server.ResponseStatusException(
					org.springframework.http.HttpStatus.BAD_REQUEST, "Unknown report view or page");
		}
		RepoScanEntity scan = scan(scanId);
		WatchtowerModelAndView mv = new WatchtowerModelAndView("repo_scan/report");
		RepoScanReport report = reports.getReport(scan).orElse(null);
		mv.addObject("scan", scan);
		mv.addObject("report", report);
		mv.addObject("view", view);
		mv.addObject("search", search);
		mv.addObject("codeFiles", report == null ? List.of() : reports.codeFiles(report));
		mv.addObject("findings", com.tracelink.appsec.watchtower.core.scan.presentation.RemoteReportModel.add(mv, "repository", scanId,
				remoteAssessments, report == null ? List.of() : report.findings().stream()
						.map(com.tracelink.appsec.watchtower.core.scan.presentation.FindingPresentationModel::fromRepository).toList()));
		// "By rule" counts the AWS assessment's rule too, not only the local scanners' (Dev walk 2026-10-22).
		@SuppressWarnings("unchecked")
		var providerStatuses = (List<com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService.Status>) mv.getModel()
				.getOrDefault("providerStatuses", List.of());
		var ruleCounts = com.tracelink.appsec.watchtower.core.scan.presentation.RemoteReportModel.withProviderRules(
				RepoScanViewService.ruleCounts(scan), providerStatuses);
		mv.addObject("ruleCounts", ruleCounts);
		mv.addObject("rulesetLabel", com.tracelink.appsec.watchtower.core.scan.presentation.ScannerIdentity
				.readableRulesetName(scan.getRulesetName()));
		// UAT #19: "By rule" and "Fixed" are addressable views with search and pages, not dialogs.
		String needle = search.strip().toLowerCase(java.util.Locale.ROOT);
		mv.addObject("ruleRows", page(ruleCounts.stream()
				.filter(e -> e.getKey().toLowerCase(java.util.Locale.ROOT).contains(needle)).toList(), page));
		List<RepoScanReport.Fixed> fixed = report == null ? List.of() : report.fixed();
		mv.addObject("fixedRows", page(fixed.stream().filter(f -> (java.util.Objects.toString(f.rule(), "") + " "
				+ java.util.Objects.toString(f.file(), "")).toLowerCase(java.util.Locale.ROOT).contains(needle)).toList(), page));
		mv.addObject("viewUrl", org.springframework.web.util.UriComponentsBuilder.fromPath("/reposcan/report/" + scanId)
				.queryParam("view", "{view}").queryParam("search", "{search}").encode()
				.buildAndExpand(view, search).toUriString());
		mv.addScriptReference("/scripts/workspace-resizer.js");
		mv.addScriptReference("/scripts/finding-workspace.js");
		mv.addScriptReference("/scripts/repo-scan.js");
		return mv;
	}

	/**
	 * One file's code for the report's Code section, fetched from the SCM at the scanned commit
	 * for this response only. Which lines are flagged, and which are masked as secrets, comes
	 * from the report, never the request.
	 */
	@GetMapping("/report/{scanId}/code")
	public String code(@PathVariable long scanId, @RequestParam String file, Model model) {
		RepoScanEntity scan = scan(scanId);
		// Only a file the report's findings name may be fetched
		RepoScanReport report = reports.getReport(scan)
				.filter(r -> reports.codeFiles(r).stream().anyMatch(f -> f.name().equals(file)))
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
		model.addAttribute("file", reports.codeFile(scan, report, file));
		model.addAttribute("link", reports.fileLink(scan, file, 0));
		return "repo_scan/code :: file";
	}

	@GetMapping("/report/{scanId}/export")
	public void export(@PathVariable long scanId,
			@RequestParam(defaultValue = "csv") String format, HttpServletResponse response)
			throws IOException {
        if (combinedExports != null) { combinedExports.export("repository", scanId, format.toLowerCase(java.util.Locale.ROOT), response); return; }
		RepoScanEntity scan = scan(scanId);
		Optional<RepoScanReport> report = reports.getReport(scan);
		if (report.isEmpty()) {
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "The report has expired");
		}
		boolean sarif = "sarif".equalsIgnoreCase(format);
		response.setContentType(sarif ? "application/sarif+json" : "text/csv");
		response.setHeader("Content-Disposition", "attachment; filename=\"repo-scan-" + scanId
				+ (sarif ? ".sarif" : ".csv") + "\"");
		if (sarif) {
			RepoScanExporter.sarif(report.get(), response.getOutputStream());
		} else {
			RepoScanExporter.csv(report.get(), response.getOutputStream());
		}
	}

	private RepoScanEntity scan(long scanId) {
		return scans.findWithRepository(scanId)
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
	}

	private static <T> com.tracelink.appsec.watchtower.core.mvc.PagedResult<T> page(List<T> rows, int page) {
		int from = (int) Math.min((long) page * REPORT_VIEW_PAGE_SIZE, rows.size());
		int to = Math.min(from + REPORT_VIEW_PAGE_SIZE, rows.size());
		return new com.tracelink.appsec.watchtower.core.mvc.PagedResult<>(rows.subList(from, to), page,
				REPORT_VIEW_PAGE_SIZE, rows.size(), (int) Math.ceil((double) rows.size() / REPORT_VIEW_PAGE_SIZE));
	}
}
