package com.tracelink.appsec.watchtower.core.cwe;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** What a person decided about one weakness in one language column (table {@code cwe_gap_decision}). */
@Entity
@Table(name = "cwe_gap_decision")
public class CweGapDecisionEntity {
	@Id
	@Column(name = "decision_key", length = 32)
	private String key;
	@Column(name = "cwe_id", nullable = false)
	private int cweId;
	@Column(name = "language", length = 16, nullable = false)
	private String language;
	@Column(name = "decision", length = 16, nullable = false)
	private String decision;
	@Column(name = "note", length = 255)
	private String note;
	@Column(name = "decided_by", length = 255, nullable = false)
	private String decidedBy;
	@Column(name = "decided_at", nullable = false)
	private long decidedAt;

	protected CweGapDecisionEntity() {
	}

	public CweGapDecisionEntity(int cweId, CoverageLanguage language, GapDecision decision, String note, String decidedBy,
			long decidedAt) {
		this.key = key(cweId, language);
		this.cweId = cweId;
		this.language = language.name();
		this.decision = decision.name();
		this.note = note;
		this.decidedBy = decidedBy;
		this.decidedAt = decidedAt;
	}

	public static String key(int cweId, CoverageLanguage language) {
		return cweId + ":" + language.name();
	}

	public int getCweId() { return cweId; }
	public CoverageLanguage getLanguage() { return CoverageLanguage.valueOf(language); }
	public GapDecision getDecision() { return GapDecision.valueOf(decision); }
	public String getNote() { return note; }
	public String getDecidedBy() { return decidedBy; }
	public long getDecidedAt() { return decidedAt; }
}
