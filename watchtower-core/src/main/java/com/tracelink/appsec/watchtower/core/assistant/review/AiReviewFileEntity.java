package com.tracelink.appsec.watchtower.core.assistant.review;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** One file of a review run and how far it got (table {@code ai_review_file}). Only the path is kept, never the code. */
@Entity
@Table(name = "ai_review_file")
public class AiReviewFileEntity {
	public static final String PENDING = "PENDING", DONE = "DONE", SKIPPED = "SKIPPED", NO_ANSWER = "NO_ANSWER";

	@Id
	@Column(name = "file_id", length = 36)
	private String fileId;
	@Column(name = "run_id", length = 36, nullable = false)
	private String runId;
	@Column(name = "path", length = 255, nullable = false)
	private String path;
	@Column(name = "status", length = 16, nullable = false)
	private String status;
	@Column(name = "note", length = 200)
	private String note;

	protected AiReviewFileEntity() {
	}

	public AiReviewFileEntity(String fileId, String runId, String path) {
		this.fileId = fileId;
		this.runId = runId;
		this.path = path;
		this.status = PENDING;
	}

	public String getFileId() { return fileId; }
	public String getRunId() { return runId; }
	public String getPath() { return path; }
	public String getStatus() { return status; }
	public String getNote() { return note; }

	public void finish(String newStatus, String why) {
		this.status = newStatus;
		this.note = why == null ? null : why.substring(0, Math.min(200, why.length()));
	}
}
