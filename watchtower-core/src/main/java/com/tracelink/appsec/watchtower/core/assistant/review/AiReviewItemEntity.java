package com.tracelink.appsec.watchtower.core.assistant.review;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * One thing the AI review noticed in a file: where, which weakness, why, and whether a scanner finding of the same
 * scan already covers it (table {@code ai_review_item}). A person confirms or dismisses it; the review decides nothing.
 */
@Entity
@Table(name = "ai_review_item")
public class AiReviewItemEntity {
	public static final String COVERED = "COVERED", GAP = "GAP", NOT_CHECKED = "NOT_CHECKED";
	public static final String OPEN = "OPEN", CONFIRMED = "CONFIRMED", DISMISSED = "DISMISSED", DRAFTED = "DRAFTED";

	@Id
	@Column(name = "item_id", length = 36)
	private String itemId;
	@Column(name = "run_id", length = 36, nullable = false)
	private String runId;
	@Column(name = "path", length = 255, nullable = false)
	private String path;
	@Column(name = "first_line", nullable = false)
	private int firstLine;
	@Column(name = "last_line", nullable = false)
	private int lastLine;
	@Column(name = "cwe", length = 16, nullable = false)
	private String cwe;
	@Column(name = "rationale", length = 300, nullable = false)
	private String rationale;
	@Column(name = "confidence", length = 8, nullable = false)
	private String confidence;
	@Column(name = "engine_hint", length = 16)
	private String engineHint;
	@Column(name = "coverage", length = 12, nullable = false)
	private String coverage;
	@Column(name = "covered_by", length = 120)
	private String coveredBy;
	@Column(name = "state", length = 12, nullable = false)
	private String state;
	@Column(name = "decided_by")
	private String decidedBy;
	@Column(name = "decided_at")
	private Long decidedAt;
	@Column(name = "created_at", nullable = false)
	private long createdAt;

	protected AiReviewItemEntity() {
	}

	public AiReviewItemEntity(String itemId, String runId, String path, int firstLine, int lastLine, String cwe, String rationale,
			String confidence, String engineHint, String coverage, String coveredBy, long now) {
		this.itemId = itemId;
		this.runId = runId;
		this.path = path;
		this.firstLine = firstLine;
		this.lastLine = lastLine;
		this.cwe = cwe;
		this.rationale = rationale;
		this.confidence = confidence;
		this.engineHint = engineHint;
		this.coverage = coverage;
		this.coveredBy = coveredBy;
		this.state = OPEN;
		this.createdAt = now;
	}

	public String getItemId() { return itemId; }
	public String getRunId() { return runId; }
	public String getPath() { return path; }
	public int getFirstLine() { return firstLine; }
	public int getLastLine() { return lastLine; }
	public String getCwe() { return cwe; }
	public String getRationale() { return rationale; }
	public String getConfidence() { return confidence; }
	public String getEngineHint() { return engineHint; }
	public String getCoverage() { return coverage; }
	public String getCoveredBy() { return coveredBy; }
	public String getState() { return state; }
	public String getDecidedBy() { return decidedBy; }
	public Long getDecidedAt() { return decidedAt; }

	public void decide(String newState, String by, long at) {
		this.state = newState;
		this.decidedBy = by;
		this.decidedAt = at;
	}
}
