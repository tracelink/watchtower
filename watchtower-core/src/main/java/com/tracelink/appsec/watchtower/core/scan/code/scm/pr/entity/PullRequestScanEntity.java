package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity;

import java.util.List;

import jakarta.persistence.*;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestMCRStatus;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestMCRStatus.PullRequestMCRStatusConverter;

/**
 * Scan Entity class for Pull Requests with join to {@linkplain PullRequestContainerEntity} and
 * reverse join to {@linkplain PullRequestViolationEntity}
 * 
 * @author csmith
 *
 */
@Entity
@Table(name = "pull_request_scans")
public class PullRequestScanEntity
		extends AbstractScanEntity<PullRequestContainerEntity, PullRequestViolationEntity> {
    @Column(name = "provider_summary_json", columnDefinition = "TEXT")
    private String providerSummaryJson;
    public String getProviderSummaryJson() { return providerSummaryJson; }
    public void setProviderSummaryJson(String json) { providerSummaryJson = json; }
    public java.util.List<com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference> getProviderAssessments() {
        return com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference.decode(providerSummaryJson);
    }
    public int getProviderFindingCount() { return getProviderAssessments().stream().mapToInt(r -> r.status().imported()).sum(); }

	@Column(name = "remote_assessment_state", length = 32)
	private String remoteAssessmentState;
	@Column(name = "remote_completed_at") private Long remoteCompletedAt;
	public Long getRemoteCompletedAt() { return remoteCompletedAt; }
	public void setRemoteCompletedAt(Long time) { remoteCompletedAt = time; }
	public String getRemoteAssessmentState() { return remoteAssessmentState; }
	public void setRemoteAssessmentState(String state) { remoteAssessmentState = state; }

	@Column(name = "execution_snapshot_json", columnDefinition = "LONGTEXT")
	private String executionSnapshotJson;

	public String getExecutionSnapshotJson() { return executionSnapshotJson; }
	public void setExecutionSnapshotJson(String json) { executionSnapshotJson = json; }


	@Column(name = "mcr_status")
	@Convert(converter = PullRequestMCRStatusConverter.class)
	private PullRequestMCRStatus mcrStatus;

	/**
	 * Byte size of the source actually scanned for this PR scan. Under the CHANGED_FILES
	 * scope (Phase 2 of IMPROVEMENT_PLAN.md) this reflects only the changed files fetched,
	 * not a full repo checkout.
	 */
	@Column(name = "source_size_bytes")
	private long sourceSizeBytes;

	@Column(name = "total_duration_ms")
	private long totalDurationMs;

	@Column(name = "queue_wait_duration_ms")
	private long queueWaitDurationMs;

	@Column(name = "source_preparation_duration_ms")
	private long sourcePreparationDurationMs;

	@Column(name = "scanner_execution_duration_ms")
	private long scannerExecutionDurationMs;

	@Column(name = "result_processing_duration_ms")
	private long resultProcessingDurationMs;

	@Column(name = "scm_reporting_duration_ms")
	private long scmReportingDurationMs;

	@Column(name = "persistence_duration_ms")
	private long persistenceDurationMs;

	@Column(name = "cleanup_duration_ms")
	private long cleanupDurationMs;

	@Column(name = "performance_complete")
	private boolean performanceComplete;

	@Column(name = "changed_file_count")
	private int changedFileCount;

	@Column(name = "scan_scope")
	private String scanScope;

	@Column(name = "source_strategy")
	private String sourceStrategy;

	@Column(name = "scanner_timings_json", columnDefinition = "TEXT")
	private String scannerTimingsJson;

	/** The commit scanned; null for scans saved before it was recorded. */
	@Column(name = "commit_hash")
	private String commitHash;

	/**
	 * Whether this scan blocked its pull request: a new finding at or above the ruleset's blocking
	 * level that no bypass covers. Kept as a summary of the persisted finding decisions.
	 */
	@Column(name = "blocked")
	private boolean blocked;

	@ManyToOne(fetch = FetchType.EAGER)
	@JoinColumn(name = "container_id", nullable = false)
	private PullRequestContainerEntity container;

	@OneToMany(fetch = FetchType.EAGER, mappedBy = "scan")
	private List<PullRequestViolationEntity> violations;

	@Override
	public PullRequestContainerEntity getContainer() {
		return container;
	}

	@Override
	public void setContainer(PullRequestContainerEntity container) {
		this.container = container;
	}

	@Override
	public List<PullRequestViolationEntity> getViolations() {
		return violations;
	}

	public PullRequestMCRStatus getMcrStatus() {
		return mcrStatus;
	}

	public void setMcrStatus(PullRequestMCRStatus mcrStatus) { this.mcrStatus = mcrStatus;	}

	public long getSourceSizeBytes() {
		return sourceSizeBytes;
	}

	public void setSourceSizeBytes(long sourceSizeBytes) {
		this.sourceSizeBytes = sourceSizeBytes;
	}

	public long getTotalDurationMs() {
		return totalDurationMs;
	}

	public void setTotalDurationMs(long totalDurationMs) {
		this.totalDurationMs = totalDurationMs;
	}

	public long getQueueWaitDurationMs() { return queueWaitDurationMs; }

	public void setQueueWaitDurationMs(long value) { this.queueWaitDurationMs = value; }

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

	public void setSourceStrategy(String value) { this.sourceStrategy = value; }

	public String getCommitHash() { return commitHash; }

	public void setCommitHash(String value) { this.commitHash = value; }

	public boolean isBlocked() { return blocked; }

	public void setBlocked(boolean value) { this.blocked = value; }

	public String getScannerTimingsJson() { return scannerTimingsJson; }

	public void setScannerTimingsJson(String value) { this.scannerTimingsJson = value; }

}
