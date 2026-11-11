package com.tracelink.appsec.watchtower.core.rule.draft;

import com.tracelink.appsec.watchtower.core.module.designer.RuleDraftData;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** A rule drafted for one person to review in a designer (table {@code rule_draft}). It expires. */
@Entity
@Table(name = "rule_draft")
public class RuleDraftEntity {
	static final String OPEN = "OPEN", USED = "USED", DISCARDED = "DISCARDED";

	@Id
	@Column(name = "draft_id", length = 36)
	private String id;
	@Column(name = "created_by", length = 255, nullable = false)
	private String createdBy;
	@Column(name = "engine", length = 16, nullable = false)
	private String engine;
	@Column(name = "language", length = 32)
	private String language;
	@Column(name = "rule_name", length = 100, nullable = false)
	private String ruleName;
	@Column(name = "message", length = 500, nullable = false)
	private String message;
	@Column(name = "priority", nullable = false)
	private int priority;
	@Column(name = "cwe", length = 32)
	private String cwe;
	@Column(name = "secondary_cwes", length = 160)
	private String secondaryCwes;
	@Column(name = "definition", nullable = false, columnDefinition = "TEXT")
	private String definition;
	@Column(name = "file_extension", length = 32)
	private String fileExtension;
	@Column(name = "vulnerable_snippet", columnDefinition = "TEXT")
	private String vulnerableSnippet;
	@Column(name = "safe_snippet", columnDefinition = "TEXT")
	private String safeSnippet;
	@Column(name = "rationale", length = 500)
	private String rationale;
	@Column(name = "source_label", length = 120)
	private String sourceLabel;
	@Column(name = "status", length = 12, nullable = false)
	private String status;
	@Column(name = "created_at", nullable = false)
	private long createdAt;
	@Column(name = "expires_at", nullable = false)
	private long expiresAt;
	@Column(name = "used_rule_name", length = 100)
	private String usedRuleName;

	protected RuleDraftEntity() {
	}

	RuleDraftEntity(String id, String createdBy, RuleDraftData data, long createdAt, long expiresAt) {
		this.id = id;
		this.createdBy = createdBy;
		this.engine = data.engine();
		this.language = data.language();
		this.ruleName = data.name();
		this.message = data.message();
		this.priority = data.priority();
		this.cwe = data.cwe();
		this.secondaryCwes = data.secondaryCwes();
		this.definition = data.definition();
		this.fileExtension = data.fileExtension();
		this.vulnerableSnippet = data.vulnerableSnippet();
		this.safeSnippet = data.safeSnippet();
		this.rationale = data.rationale();
		this.sourceLabel = data.sourceLabel();
		this.status = OPEN;
		this.createdAt = createdAt;
		this.expiresAt = expiresAt;
	}

	RuleDraftData toData() {
		return new RuleDraftData(id, engine, language, ruleName, message, priority, cwe, secondaryCwes, definition,
				fileExtension, vulnerableSnippet, safeSnippet, rationale, sourceLabel);
	}

	void finish(String newStatus, String ruleNameUsed) {
		this.status = newStatus;
		this.usedRuleName = ruleNameUsed;
	}

	boolean isOpenAt(long now) {
		return OPEN.equals(status) && expiresAt > now;
	}

	public String getId() { return id; }
	public String getCreatedBy() { return createdBy; }
	public String getEngine() { return engine; }
	public String getStatus() { return status; }
	public long getExpiresAt() { return expiresAt; }
	public String getUsedRuleName() { return usedRuleName; }
}
