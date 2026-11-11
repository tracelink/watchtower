package com.tracelink.appsec.watchtower.core.scan.queue;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** Durable view of active PR scans and recent consumer-side validation failures. */
@Entity
@Table(name = "pr_scan_work_items")
public class PRScanWorkItemEntity {
	public enum WorkStatus { QUEUED, RUNNING, VALIDATION_FAILED }

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "work_item_id")
	private long id;

	@Column(name = "dedup_key", nullable = false, unique = true, length = 64)
	private String dedupKey;

	@Column(name = "api_label", nullable = false)
	private String apiLabel;

	@Column(name = "repo_name", nullable = false)
	private String repoName;

	@Column(name = "pr_id", nullable = false)
	private String prId;

	@Column(name = "commit_hash")
	private String commitHash;

	@Enumerated(EnumType.STRING)
	@Column(name = "status", nullable = false)
	private WorkStatus status;

	@Column(name = "enqueued_at", nullable = false)
	private long enqueuedAt;

	@Column(name = "started_at")
	private Long startedAt;

	@Column(name = "updated_at", nullable = false)
	private long updatedAt;

	@Column(name = "failure_reason", length = 1000)
	private String failureReason;

	public long getId() { return id; }
	public String getDedupKey() { return dedupKey; }
	public void setDedupKey(String value) { dedupKey = value; }
	public String getApiLabel() { return apiLabel; }
	public void setApiLabel(String value) { apiLabel = value; }
	public String getRepoName() { return repoName; }
	public void setRepoName(String value) { repoName = value; }
	public String getPrId() { return prId; }
	public void setPrId(String value) { prId = value; }
	public String getCommitHash() { return commitHash; }
	public void setCommitHash(String value) { commitHash = value; }
	public WorkStatus getStatus() { return status; }
	public void setStatus(WorkStatus value) { status = value; }
	public long getEnqueuedAt() { return enqueuedAt; }
	public void setEnqueuedAt(long value) { enqueuedAt = value; }
	public Long getStartedAt() { return startedAt; }
	public void setStartedAt(Long value) { startedAt = value; }
	public long getUpdatedAt() { return updatedAt; }
	public void setUpdatedAt(long value) { updatedAt = value; }
	public String getFailureReason() { return failureReason; }
	public void setFailureReason(String value) { failureReason = value; }
}
