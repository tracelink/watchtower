package com.tracelink.appsec.watchtower.core.scan.presentation;

import java.time.LocalDateTime;
import java.time.Instant;
import java.time.ZoneId;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResult;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanTimings;
import com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanEntity;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageScanEntity;

/** Scan-type-neutral row for the bounded recent activity table on the home page. */
public final class HomeActivityItem {
	private final String module;
	private final String target;
	private final StatusPresentationModel status;
	private final LocalDateTime completedTime;
	private final long sortTime;
	private final String duration;
	private final long findingCount;
	private final java.util.List<SeverityCountPresentationModel> severityCounts;
	private final String reportUrl;
	private String targetUrl;
	private long mcrCount;
	private String mcrReportUrl;
	private long providerFindingCount;
	private String providerLabel = "remote";
	private boolean providerIncomplete;
	private boolean targetExternal;
	private String detail;
	private ScannerBadge.Summary scanners = ScannerBadge.Summary.EMPTY;
	/** Pull requests only: whether the pull request is still open or was merged/declined. */
	private Boolean resolved;

	public HomeActivityItem(String module, String target, StatusPresentationModel status,
			LocalDateTime completedTime, long sortTime, String duration, long findingCount,
			String reportUrl) {
		this.module = module;
		this.target = target;
		this.status = status;
		this.completedTime = completedTime;
		this.sortTime = sortTime;
		this.duration = duration;
		this.findingCount = findingCount;
		this.severityCounts = java.util.List.of();
		this.reportUrl = reportUrl;
	}

	private HomeActivityItem(String module, String target, StatusPresentationModel status,
			LocalDateTime completedTime, long sortTime, String duration, long findingCount,
			java.util.List<SeverityCountPresentationModel> severityCounts, String reportUrl) {
		this.module = module;
		this.target = target;
		this.status = status;
		this.completedTime = completedTime;
		this.sortTime = sortTime;
		this.duration = duration;
		this.findingCount = findingCount;
		this.severityCounts = severityCounts;
		this.reportUrl = reportUrl;
	}

	public static HomeActivityItem fromPullRequest(PullRequestScanEntity scan) {
		String target = value(scan.getContainer().getRepoName(), "Unknown repository") + " #"
				+ value(scan.getContainer().getPrId(), "unknown");
		HomeActivityItem item = from("PR", target, scan, "/scan/report/" + scan.getId());
		item.resolved = scan.getContainer().isResolved();
		return item;
	}

	/** The existing PR results service has already loaded and mapped this bounded page. */
	public static HomeActivityItem fromPullRequestResult(PRScanResult result) {
		var local = new java.util.EnumMap<com.tracelink.appsec.watchtower.core.rule.RulePriority, Long>(
				com.tracelink.appsec.watchtower.core.rule.RulePriority.class);
		if (result.getViolations() != null) {
			for (var violation : result.getViolations()) {
				local.merge(com.tracelink.appsec.watchtower.core.rule.RulePriority.valueOf(
						violation.getSeverityValue()), 1L, Long::sum);
			}
		}
		var summary = ScanFindingSummary.of(local,
				result.getViolations() == null ? 0 : result.getViolations().size(),
				result.getProviderAssessments());
		long end = result.getDateMillis();
		HomeActivityItem item = new HomeActivityItem("PR", result.getDisplayName(),
				result.getStatusPresentation() == null
						? StatusPresentationModel.from((com.tracelink.appsec.watchtower.core.scan.ScanStatus) null)
						: result.getStatusPresentation(), completedTime(ProviderTiming.of(end, result.getProviderAssessments()).effectiveEnd(end)), end,
				result.hasPerformanceTimings() ? result.getTotalDurationDisplay() : "Not recorded",
				summary.total(), summary.severities(), "/scan/report/" + result.getId());
		item.resolved = result.isResolved();
		item.targetUrl = result.getPrLink() == null || result.getPrLink().isBlank()
				? null : result.getPrLink();
		item.targetExternal = item.targetUrl != null && !item.targetUrl.isBlank();
		item.mcrCount = result.getMcrCount();
		item.mcrReportUrl = "/scan/mcr/report/" + result.getId();
		item.providerFindingCount = summary.providerCount();
		item.providerLabel = providerLabel(result.getProviderAssessments());
		item.providerIncomplete = summary.providerIncomplete();
		item.scanners = result.getScannerTiles() == null
				? ScannerBadge.Summary.EMPTY : result.getScannerTiles();
		item.detail = result.getApiLabel() + " · " + item.getStateLabel();
		return item;
	}

	/** A lightweight PR projection for mixed result lists, with finding counts read in one batch. */
	public static HomeActivityItem fromPullRequestRow(PRScanRepository.ResultRow row,
			java.util.Map<com.tracelink.appsec.watchtower.core.rule.RulePriority, Long> local,
			long mcrCount) {
		var providers = ProviderAssessmentReference.decode(row.getProviderSummaryJson());
		long localTotal = local.values().stream().mapToLong(Long::longValue).sum();
		var summary = ScanFindingSummary.of(local, localTotal, providers);
		long end = row.getEndDate();
		var timing = ProviderTiming.of(end, providers);
		String target = value(row.getRepoName(), "Unknown repository") + " #"
				+ value(row.getPrId(), "unknown");
		HomeActivityItem item = new HomeActivityItem("PR", target,
				StatusPresentationModel.from(row.getStatus()), completedTime(timing.effectiveEnd(end)), end,
				timing.duration(row.getStartDate(), end), summary.total(), summary.severities(),
				"/scan/report/" + row.getId());
		item.resolved = row.isResolved();
		item.targetUrl = item.reportUrl;
		item.mcrCount = mcrCount;
		item.mcrReportUrl = "/scan/mcr/report/" + row.getId();
		item.providerFindingCount = summary.providerCount();
		item.providerLabel = providerLabel(providers);
		item.providerIncomplete = summary.providerIncomplete();
		item.scanners = ScannerBadge.fromReferences(
				PRScanTimings.executions(row.getScannerTimingsJson(), row.getScannerExecutionsJson()),
				providers);
		item.detail = row.getApiLabel() + " · " + item.getStateLabel();
		return item;
	}

	public static HomeActivityItem fromUpload(UploadScanEntity scan) {
		String ticket = value(scan.getContainer().getTicket(), "No ticket");
		String target = value(scan.getContainer().getName(), "Unnamed upload") + " · " + ticket;
		return from("Upload", target, scan, "/uploadscan/report/" + ticket);
	}

	public static HomeActivityItem fromImage(ImageScanEntity scan) {
		String target = value(scan.getContainer().getRepositoryName(), "Unknown image") + ":"
				+ value(scan.getContainer().getTagName(), "latest");
		return from("Image", target, scan, "/imagescan/report/" + scan.getId());
	}

	/**
	 * A repository scan: its findings are counted on the row (the report is in the report
	 * store), so the repository must be fetched with the scan.
	 */
	public static HomeActivityItem fromRepo(RepoScanEntity scan) {
		String target = value(scan.getRepository().getRepoName(), "Unknown repository") + "@"
				+ value(scan.getBranch(), "default");
		long end = scan.getEndDate();
		var timing = ProviderTiming.ofJson(end, scan.getProviderSummaryJson());
		var summary = ScanFindingSummary.of(scan.getSeverityCounts(), scan.getFindingCount(),
				scan.getProviderAssessments());
		HomeActivityItem item = new HomeActivityItem("Repository", target,
				StatusPresentationModel.from(scan), completedTime(timing.effectiveEnd(end)), end,
				timing.duration(scan.getStartDate(), end), summary.total(),
				summary.severities(),
				"/reposcan/report/" + scan.getId());
		item.targetUrl = "/repositories/" + scan.getRepository().getId() + "?view=all";
		item.providerFindingCount = summary.providerCount();
		item.providerLabel = providerLabel(scan.getProviderAssessments());
		item.providerIncomplete = summary.providerIncomplete();
		item.scanners = ScannerBadge.from(scan.getScannerExecutionsJson(), scan.getProviderSummaryJson());
		item.detail = scan.getRepository().getApiLabel() + " · Run " + scan.getRunNo();
		return item;
	}

	private static HomeActivityItem from(String module, String target,
			AbstractScanEntity<?, ?> scan, String reportUrl) {
		long end = scan.getEndDateMillis();
		var timing = scan instanceof PullRequestScanEntity prEntity
				? ProviderTiming.ofJson(end, prEntity.getProviderSummaryJson()) : ProviderTiming.NONE;
		var localFindings = scan.getViolations() == null ? java.util.List.<com.tracelink.appsec.watchtower.core.scan.AbstractScanViolationEntity<?>>of()
				: scan.getViolations().stream().filter(v -> !(scan instanceof PullRequestScanEntity)
						|| !java.util.Objects.toString(v.getViolationName(), "").startsWith("MCR Match:")).toList();
		long findings = localFindings.size();
		var localCounts = new java.util.EnumMap<com.tracelink.appsec.watchtower.core.rule.RulePriority, Long>(
				com.tracelink.appsec.watchtower.core.rule.RulePriority.class);
		for (var violation : localFindings) {
			localCounts.merge(violation.getSeverity() == null
					? com.tracelink.appsec.watchtower.core.rule.RulePriority.INFORMATIONAL
					: violation.getSeverity(), 1L, Long::sum);
		}
		var summary = ScanFindingSummary.of(localCounts, findings,
				scan instanceof PullRequestScanEntity pr ? pr.getProviderAssessments() : java.util.List.of());
		var item = new HomeActivityItem(module, target, StatusPresentationModel.fromScan(scan),
				completedTime(timing.effectiveEnd(end)), end, timing.duration(scan.getStartDateMillis(), end), summary.total(),
				summary.severities(), reportUrl);
		if (scan instanceof PullRequestScanEntity pr) {
			item.mcrCount = scan.getViolations() == null ? 0 : scan.getViolations().size() - findings;
			item.mcrReportUrl = "/scan/mcr/report/" + scan.getId();
			item.providerFindingCount = summary.providerCount();
			item.providerLabel = providerLabel(pr.getProviderAssessments());
			item.providerIncomplete = summary.providerIncomplete();
			// PR scans store the scanners that ran as timings, the rest as executions.
			item.scanners = ScannerBadge.from(com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanTimings
					.executions(pr.getScannerTimingsJson(), pr.getScannerExecutionsJson()), pr.getProviderSummaryJson());
		} else {
			item.scanners = ScannerBadge.from(scan.getScannerExecutionsJson(), null);
		}
		return item;
	}

	private static LocalDateTime completedTime(long end) {
		return end > 0
				? LocalDateTime.ofInstant(Instant.ofEpochMilli(end), ZoneId.systemDefault()) : null;
	}

	/** One duration format for every scan list: "850 ms", "8.00 s", "2.50 mins" or "Not recorded". */
	public static String formatDuration(long start, long end) {
		return duration(start, end);
	}

	private static String duration(long start, long end) {
		if (start <= 0 || end < start) return "Not recorded";
		return DurationText.of(end - start);
	}

	private static String value(String value, String fallback) {
		return value == null || value.isBlank() ? fallback : value;
	}

	private static String providerLabel(java.util.List<ProviderAssessmentReference> providers) {
		if (providers != null && !providers.isEmpty() && providers.stream()
				.allMatch(p -> p.provider() != null && p.provider().toLowerCase(java.util.Locale.ROOT)
						.contains("aws"))) return "AWS";
		return "remote";
	}

	public String getModule() { return module; }
	/** "Open" or "Resolved" for a pull request; null for other scan types. */
	public String getStateLabel() { return resolved == null ? null : resolved ? "Resolved" : "Open"; }
	public String getStateIcon() { return Boolean.TRUE.equals(resolved) ? "task_alt" : "radio_button_unchecked"; }
	public String getStateTip() {
		return Boolean.TRUE.equals(resolved) ? "The pull request was merged or declined" : "The pull request is still open";
	}
	/** The scan type for people, shown under the target ("Pull request" rather than "PR"). */
	public String getKindLabel() { return "PR".equals(module) ? "Pull request" : module; }
	/** The same icon the sidebar uses for this scan type. */
	public String getKindIcon() {
		return switch (module) {
			case "PR" -> "compare_arrows";
			case "Upload" -> "backup";
			case "Image" -> "developer_board";
			default -> "code";
		};
	}
	/** Tiles for the scanners that took part, plus those not used; empty for older scans. */
	public ScannerBadge.Summary getScanners() { return scanners; }
	public String getTarget() { return target; }
	public String getDetail() { return detail; }
	public StatusPresentationModel getStatus() { return status; }
	public LocalDateTime getCompletedTime() { return completedTime; }
	public long getSortTime() { return sortTime; }
	public String getDuration() { return duration; }
	public long getFindingCount() { return findingCount; }
	public long getMcrCount() { return mcrCount; }
	public String getMcrReportUrl() { return mcrReportUrl; }
	public long getProviderFindingCount() { return providerFindingCount; }
	public String getProviderLabel() { return providerLabel; }
	public boolean isProviderIncomplete() { return providerIncomplete; }
	public boolean isTargetExternal() { return targetExternal; }
	public java.util.List<SeverityCountPresentationModel> getSeverityCounts() {
		return severityCounts;
	}
	public String getReportUrl() { return reportUrl; }
	/** @return where the target itself is described (a repository's page), or null */
	public String getTargetUrl() { return targetUrl; }
}
