package com.tracelink.appsec.watchtower.core.rule;

import jakarta.persistence.Column;
import jakarta.persistence.Embedded;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** Append-only metadata snapshots; no cascading relationship to mutable rule definitions. */
@Entity
@Table(name = "rule_stewardship_history")
public class RuleStewardshipHistoryEntity {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "history_id")
	private Long id;
	@Column(name = "rule_id", nullable = false)
	private long ruleId;
	@Column(name = "changed_by", nullable = false, length = 255)
	private String changedBy;
	@Column(name = "changed_at", nullable = false)
	private long changedAt;
	@Embedded
	private RuleStewardship stewardship;

	protected RuleStewardshipHistoryEntity() { }

	public RuleStewardshipHistoryEntity(RuleEntity rule, String changedBy) {
		this.ruleId = rule.getId();
		this.changedBy = changedBy;
		this.changedAt = System.currentTimeMillis();
		this.stewardship = rule.getStewardship().copy();
	}

	public Long getId() { return id; }
	public long getRuleId() { return ruleId; }
	public String getChangedBy() { return changedBy; }
	public long getChangedAt() { return changedAt; }
	public RuleStewardship getStewardship() { return stewardship; }
}
