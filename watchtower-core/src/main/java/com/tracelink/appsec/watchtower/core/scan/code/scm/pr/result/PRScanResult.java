package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestMCRStatus;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestState;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanTimings;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary;
import com.tracelink.appsec.watchtower.core.scan.presentation.StatusPresentationModel;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import com.tracelink.appsec.watchtower.core.scan.presentation.DurationText;

/**
 * Helper class to hold important information about the results of a PR scan
 * 
 * @author csmith
 *
 */
public class PRScanResult {
    private java.util.List<com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference> providerAssessments = java.util.List.of();
    public java.util.List<com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference> getProviderAssessments() { return providerAssessments; }
    public void setProviderAssessments(java.util.List<com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference> value) { providerAssessments = java.util.List.copyOf(value); }
    public int getProviderFindingCount() { return providerAssessments.stream().mapToInt(r -> r.status().imported()).sum(); }
    public boolean isProviderComplete() { return providerAssessments.stream().allMatch(r -> r.status().complete()); }

	private long id;

	private String prId;

	private String displayName;

	private String author;

	private LocalDateTime date;

	private StatusPresentationModel statusPresentation;

	private String prLink;

	private String apiLabel;

	private String repoName;

	private List<PRScanResultViolation> violations;

	private PullRequestMCRStatus mcrStatus;

	/** MERGED or DECLINED once the SCM said so; null while open and for older pull requests. */
	private PullRequestState closedState;

	/** Whether the pull request is resolved: closed, or nothing new to review. */
	private boolean resolved;

	private long queueWaitDurationMs;

	private long totalDurationMs;

	private long sourcePreparationDurationMs;

	private long scannerExecutionDurationMs;

	private long resultProcessingDurationMs;

	private long scmReportingDurationMs;

	private long sourceSizeBytes;
	private long persistenceDurationMs;
	private long cleanupDurationMs;
	private boolean performanceComplete;
	private int changedFileCount;
	private String scanScope;
	private String sourceStrategy;
	private List<PRScanTimings.ScannerTiming> scannerTimings = Collections.emptyList();
	private ScanExecutionSummary executionSummary =
			new ScanExecutionSummary(null, Collections.emptyList());

	private List<PRScanResultViolation> mcrFindings;

	// The source behind the findings above, one entry per file that HAS findings, rendered in the
	// code section at the bottom of the report. Only populated for the single-scan report view
	// (PRScanResultService.getScanResultForScanId) - list views deliberately leave this empty
	// rather than fetch file content per row, which would reintroduce the per-row latency already
	// fixed there.
	private List<PRScanResultFile> codeFiles = Collections.emptyList();

	// Same idea as codeFiles above, but keyed off mcrFindings instead of violations - the MCR
	// report renders its own Code section, separate from the PR scan report's, so a file's
	// finding count in one never has to agree with the other.
	private List<PRScanResultFile> mcrCodeFiles = Collections.emptyList();

	public void setId(long id) {
		this.id = id;
	}

	public long getId() {
		return this.id;
	}

	public PullRequestState getClosedState() {
		return closedState;
	}

	public void setClosedState(PullRequestState closedState) {
		this.closedState = closedState;
	}

	public boolean isResolved() {
		return resolved;
	}

	public void setResolved(boolean resolved) {
		this.resolved = resolved;
	}

	public String getPrId() {
		return prId;
	}

	public void setPrId(String id) {
		this.prId = id;
	}

	public String getDisplayName() {
		return displayName;
	}

	public void setDisplayName(String displayName) {
		this.displayName = displayName;
	}

	public String getAuthor() {
		return author;
	}

	public void setAuthor(String author) {
		this.author = author;
	}

	public LocalDateTime getDate() {
		return date;
	}

	public void setDate(LocalDateTime date) {
		this.date = date;
	}

	public long getDateMillis() {
		return com.tracelink.appsec.watchtower.core.ui.ServerTime.toEpochMillis(date);
	}

	@JsonIgnore
	public StatusPresentationModel getStatusPresentation() {
		return statusPresentation;
	}

	public void setStatusPresentation(StatusPresentationModel statusPresentation) {
		this.statusPresentation = statusPresentation;
	}

	public String getPrLink() {
		return prLink;
	}

	public void setPrLink(String prLink) {
		this.prLink = prLink;
	}

	public String getApiLabel() {
		return apiLabel;
	}

	public void setApiLabel(String apiLabel) {
		this.apiLabel = apiLabel;
	}

	public String getRepoName() {
		return repoName;
	}

	public void setRepoName(String repoName) {
		this.repoName = repoName;
	}

	public List<PRScanResultViolation> getViolations() {
		return violations;
	}

	public void setViolations(List<PRScanResultViolation> violations) {
		this.violations = violations;
	}

	public List<PRScanResultViolation> getMcrFindings() { return mcrFindings; }
	public int getFindingCount() { return (violations == null ? 0 : violations.size()) + getProviderFindingCount(); }
	public int getMcrCount() { return mcrFindings == null ? 0 : mcrFindings.size(); }

	public void setMcrFindings(List<PRScanResultViolation> mcrFindings) {this.mcrFindings = mcrFindings; }

	public void setMcrStatus(PullRequestMCRStatus mcrStatus) { this.mcrStatus = mcrStatus; }

	public PullRequestMCRStatus getMcrStatus() {return mcrStatus; }

	public long getQueueWaitDurationMs() {
		return queueWaitDurationMs;
	}

	public void setQueueWaitDurationMs(long queueWaitDurationMs) {
		this.queueWaitDurationMs = Math.max(0, queueWaitDurationMs);
	}

	public long getTotalDurationMs() {
		return totalDurationMs;
	}

	public void setTotalDurationMs(long totalDurationMs) {
		this.totalDurationMs = totalDurationMs;
	}

	public long getSourcePreparationDurationMs() {
		return sourcePreparationDurationMs;
	}

	public void setSourcePreparationDurationMs(long sourcePreparationDurationMs) {
		this.sourcePreparationDurationMs = sourcePreparationDurationMs;
	}

	public long getScannerExecutionDurationMs() {
		return scannerExecutionDurationMs;
	}

	public void setScannerExecutionDurationMs(long scannerExecutionDurationMs) {
		this.scannerExecutionDurationMs = scannerExecutionDurationMs;
	}

	public long getResultProcessingDurationMs() {
		return resultProcessingDurationMs;
	}

	public void setResultProcessingDurationMs(long resultProcessingDurationMs) {
		this.resultProcessingDurationMs = resultProcessingDurationMs;
	}

	public long getScmReportingDurationMs() {
		return scmReportingDurationMs;
	}

	public void setScmReportingDurationMs(long scmReportingDurationMs) {
		this.scmReportingDurationMs = scmReportingDurationMs;
	}

	public long getSourceSizeBytes() {
		return sourceSizeBytes;
	}

	public void setSourceSizeBytes(long sourceSizeBytes) {
		this.sourceSizeBytes = sourceSizeBytes;
	}

	public long getPersistenceDurationMs() { return persistenceDurationMs; }
	public void setPersistenceDurationMs(long value) { this.persistenceDurationMs = value; }
	public long getCleanupDurationMs() { return cleanupDurationMs; }
	public void setCleanupDurationMs(long value) { this.cleanupDurationMs = value; }
	public boolean isPerformanceComplete() { return performanceComplete; }
	public void setPerformanceComplete(boolean value) { this.performanceComplete = value; }
	public int getChangedFileCount() { return changedFileCount; }
	public void setChangedFileCount(int value) { this.changedFileCount = value; }
	public String getScanScope() { return scanScope; }
	public void setScanScope(String value) { this.scanScope = value; }
	public String getSourceStrategy() { return sourceStrategy; }

	/** In words, how the scan got the source: one by one, or the whole repository above the threshold. */
	public String getSourceStrategyText() {
		String base = sourceStrategy == null ? "" : sourceStrategy.replace("_PRUNED", "");
		String files = changedFileCount + (changedFileCount == 1 ? " changed file" : " changed files");
		return switch (base) {
			case "INDIVIDUAL_FILES" -> "Read the " + files + " one by one.";
			case "FULL_DOWNLOAD" -> "Downloaded the whole repository because " + files
					+ " is above the full-source threshold (PR settings).";
			case "CACHED_ARCHIVE" -> "Used a cached copy of the whole repository (" + files + ").";
			case "MANIFEST_FILES" -> "Read the " + files + " and the dependency manifests.";
			default -> null;
		};
	}
	public void setSourceStrategy(String value) { this.sourceStrategy = value; }
	public List<PRScanTimings.ScannerTiming> getScannerTimings() { return scannerTimings; }
	public void setScannerTimings(List<PRScanTimings.ScannerTiming> value) {
		this.scannerTimings = value == null ? Collections.emptyList() : List.copyOf(value);
	}
	public ScanExecutionSummary getExecutionSummary() { return executionSummary; }
	public void setExecutionSummary(ScanExecutionSummary value) {
		this.executionSummary = value == null
				? new ScanExecutionSummary(null, Collections.emptyList()) : value;
	}
	public String getPersistenceDurationDisplay() { return formatDuration(persistenceDurationMs); }
	public String getCleanupDurationDisplay() { return formatDuration(cleanupDurationMs); }
	public String getDeliveryDurationDisplay() {
		return formatDuration(resultProcessingDurationMs + scmReportingDurationMs
				+ persistenceDurationMs);
	}

	/** The report's scanner tiles, the same as Home's Scanners column. */
	public com.tracelink.appsec.watchtower.core.scan.presentation.ScannerBadge.Summary getScannerTiles() {
		return com.tracelink.appsec.watchtower.core.scan.presentation.ScannerBadge.fromReferences(
				executionSummary.scanners(), providerAssessments);
	}

	/**
	 * Width of one stage on the report's timing bar ("prepare", "analysis" or "deliver") as a CSS
	 * percentage of the three stages together.
	 */
	public String getStageWidth(String stage) {
		long deliver = resultProcessingDurationMs + scmReportingDurationMs + persistenceDurationMs;
		long analysis = scannerExecutionDurationMs + providerWait().extraMs();
		long total = sourcePreparationDurationMs + analysis + deliver;
		long part = switch (stage) {
			case "prepare" -> sourcePreparationDurationMs;
			case "analysis" -> analysis;
			default -> deliver;
		};
		return total <= 0 ? "0%" : String.format(java.util.Locale.ROOT, "%.1f%%", 100.0 * part / total);
	}

	public boolean hasPerformanceTimings() {
		return performanceComplete;
	}

	public String getQueueWaitDurationDisplay() {
		return formatDuration(queueWaitDurationMs);
	}

	/**
	 * The scan's whole duration: Watchtower's own time plus the time its AWS review kept the scan open afterwards, or
	 * "Running" while that review is still working. Without this the total would stop when the local result was saved.
	 */
	public String getTotalDurationDisplay() {
		var wait = providerWait();
		return wait.pending() ? "Running" : formatDuration(totalDurationMs + wait.extraMs());
	}

	private com.tracelink.appsec.watchtower.core.scan.presentation.ProviderTiming providerWait() {
		return providerAssessments.isEmpty() || date == null
				? com.tracelink.appsec.watchtower.core.scan.presentation.ProviderTiming.NONE
				: com.tracelink.appsec.watchtower.core.scan.presentation.ProviderTiming.of(getDateMillis(), providerAssessments);
	}

	public String getSourcePreparationDurationDisplay() {
		return formatDuration(sourcePreparationDurationMs);
	}

	/** Security analysis includes the AWS review's time, which is analysis too. */
	public String getScannerExecutionDurationDisplay() {
		var wait = providerWait();
		return wait.pending() ? "Running" : formatDuration(scannerExecutionDurationMs + wait.extraMs());
	}

	public String getResultProcessingDurationDisplay() {
		return formatDuration(resultProcessingDurationMs);
	}

	public String getScmReportingDurationDisplay() {
		return formatDuration(scmReportingDurationMs);
	}

	public String getSourceSizeDisplay() {
		if (sourceSizeBytes < 1024) {
			return sourceSizeBytes + " B";
		}
		String[] units = {"KB", "MB", "GB", "TB"};
		double value = sourceSizeBytes;
		int unit = -1;
		do {
			value /= 1024.0;
			unit++;
		} while (value >= 1024 && unit < units.length - 1);
		return String.format(Locale.ROOT, "%.1f %s", value, units[unit]);
	}

	public String formatDuration(long durationMs) {
		if (durationMs < 1000) {
			return durationMs + " ms";
		}
		if (durationMs < 60_000) {
			return String.format(Locale.ROOT, "%.1f s", durationMs / 1000.0);
		}
		return DurationText.minutesAndSeconds(durationMs);
	}

	public List<PRScanResultFile> getCodeFiles() {
		return codeFiles;
	}

	public void setCodeFiles(List<PRScanResultFile> codeFiles) {
		this.codeFiles = List.copyOf(codeFiles);
	}

	public List<PRScanResultFile> getMcrCodeFiles() {
		return mcrCodeFiles;
	}

	public void setMcrCodeFiles(List<PRScanResultFile> mcrCodeFiles) {
		this.mcrCodeFiles = List.copyOf(mcrCodeFiles);
	}

}
