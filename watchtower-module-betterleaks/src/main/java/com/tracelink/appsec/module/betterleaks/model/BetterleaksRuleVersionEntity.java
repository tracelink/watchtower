package com.tracelink.appsec.module.betterleaks.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * One saved version of a custom Betterleaks rule. Append-only: core rules have no history, so a
 * secrets rule's changes - which decide what blocks a pull request - are kept here.
 *
 * @author Watchtower
 */
@Entity
@Table(name = "betterleaks_rule_versions")
public class BetterleaksRuleVersionEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "version_id")
	private long id;

	@Column(name = "rule_id")
	private long ruleId;

	@Column(name = "rule_version")
	private int ruleVersion;

	/** The rule's fields as JSON, exactly as saved. */
	@Column(name = "definition")
	private String definition;

	@Column(name = "author")
	private String author;

	@Column(name = "created_at")
	private long createdAt;

	public long getId() {
		return id;
	}

	public long getRuleId() {
		return ruleId;
	}

	public void setRuleId(long ruleId) {
		this.ruleId = ruleId;
	}

	public int getRuleVersion() {
		return ruleVersion;
	}

	public void setRuleVersion(int ruleVersion) {
		this.ruleVersion = ruleVersion;
	}

	public String getDefinition() {
		return definition;
	}

	public void setDefinition(String definition) {
		this.definition = definition;
	}

	public String getAuthor() {
		return author;
	}

	public void setAuthor(String author) {
		this.author = author;
	}

	public long getCreatedAt() {
		return createdAt;
	}

	public void setCreatedAt(long createdAt) {
		this.createdAt = createdAt;
	}
}
