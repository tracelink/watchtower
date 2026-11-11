package com.tracelink.appsec.watchtower.core.assistant.review;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** One AI review of the files a person picked from one scan (table {@code ai_review_run}). Holds counts and times only. */
@Entity
@Table(name = "ai_review_run")
public class AiReviewRunEntity {
	public static final String QUEUED = "QUEUED", RUNNING = "RUNNING", DONE = "DONE", PARTIAL_BUDGET = "PARTIAL_BUDGET", FAILED = "FAILED";

	@Id
	@Column(name = "run_id", length = 36)
	private String runId;
	@Column(name = "scan_type", length = 16, nullable = false)
	private String scanType;
	@Column(name = "scan_id", nullable = false)
	private long scanId;
	@Column(name = "requested_by", nullable = false)
	private String requestedBy;
	@Column(name = "status", length = 16, nullable = false)
	private String status;
	@Column(name = "files_total", nullable = false)
	private int filesTotal;
	@Column(name = "files_done", nullable = false)
	private int filesDone;
	@Column(name = "items", nullable = false)
	private int items;
	@Column(name = "created_at", nullable = false)
	private long createdAt;
	@Column(name = "finished_at")
	private Long finishedAt;
	@Column(name = "expires_at", nullable = false)
	private long expiresAt;
	@Column(name = "focus", length = 500)
	private String focus;

	protected AiReviewRunEntity() {
	}

	public AiReviewRunEntity(String runId, String scanType, long scanId, String requestedBy, int filesTotal, long now, long expiresAt) {
		this.runId = runId;
		this.scanType = scanType;
		this.scanId = scanId;
		this.requestedBy = requestedBy;
		this.status = QUEUED;
		this.filesTotal = filesTotal;
		this.createdAt = now;
		this.expiresAt = expiresAt;
	}

	public String getRunId() { return runId; }
	public String getScanType() { return scanType; }
	public long getScanId() { return scanId; }
	public String getRequestedBy() { return requestedBy; }
	public String getStatus() { return status; }
	public int getFilesTotal() { return filesTotal; }
	public int getFilesDone() { return filesDone; }
	public int getItems() { return items; }
	public long getCreatedAt() { return createdAt; }
	public Long getFinishedAt() { return finishedAt; }
	public long getExpiresAt() { return expiresAt; }
	/** The person's note about what to look at, or null. */
	public String getFocus() { return focus; }

	/** Set once, when the run is made; a resumed run keeps it. */
	public void setFocus(String focus) {
		this.focus = focus;
	}

	public void setStatus(String status, Long finishedAt) {
		this.status = status;
		this.finishedAt = finishedAt;
	}

	public void fileDone(int newItems) {
		this.filesDone++;
		this.items += newItems;
	}
}
