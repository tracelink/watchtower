package com.tracelink.appsec.module.betterleaks.allowlist;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * A persisted Betterleaks allowlist entry. Holds only paths, rule ids and who/why - never a
 * secret or a hash of one.
 *
 * @author Watchtower
 */
@Entity
@Table(name = "betterleaks_allowlist")
public class BetterleaksAllowlistEntryEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "entry_id")
	private long id;

	@Column(name = "scope")
	@Enumerated(EnumType.STRING)
	private BetterleaksAllowlistScope scope;

	@Column(name = "repo_name")
	private String repoName;

	@Column(name = "path_glob")
	private String pathGlob;

	@Column(name = "rule_id")
	private String ruleId;

	@Column(name = "reason")
	private String reason;

	@Column(name = "created_by")
	private String createdBy;

	@Column(name = "created_at")
	private long createdAt;

	@Column(name = "expires_at")
	private Long expiresAt;

	public long getId() {
		return id;
	}

	public BetterleaksAllowlistScope getScope() {
		return scope;
	}

	public void setScope(BetterleaksAllowlistScope scope) {
		this.scope = scope;
	}

	public String getRepoName() {
		return repoName;
	}

	public void setRepoName(String repoName) {
		this.repoName = repoName;
	}

	public String getPathGlob() {
		return pathGlob;
	}

	public void setPathGlob(String pathGlob) {
		this.pathGlob = pathGlob;
	}

	public String getRuleId() {
		return ruleId;
	}

	public void setRuleId(String ruleId) {
		this.ruleId = ruleId;
	}

	public String getReason() {
		return reason;
	}

	public void setReason(String reason) {
		this.reason = reason;
	}

	public String getCreatedBy() {
		return createdBy;
	}

	public void setCreatedBy(String createdBy) {
		this.createdBy = createdBy;
	}

	public long getCreatedAt() {
		return createdAt;
	}

	public void setCreatedAt(long createdAt) {
		this.createdAt = createdAt;
	}

	/**
	 * @return the epoch-millisecond instant from which the entry no longer applies, or null
	 */
	public Long getExpiresAt() {
		return expiresAt;
	}

	public void setExpiresAt(Long expiresAt) {
		this.expiresAt = expiresAt;
	}

	/**
	 * @return the last day (UTC) the entry applies, for display; null if it never expires
	 */
	public LocalDate getLastDay() {
		return expiresAt == null ? null
				: Instant.ofEpochMilli(expiresAt).atZone(ZoneOffset.UTC).toLocalDate()
						.minusDays(1);
	}

	/**
	 * @param nowMillis the current time
	 * @return true if the entry has expired
	 */
	public boolean isExpired(long nowMillis) {
		return expiresAt != null && expiresAt <= nowMillis;
	}

	/**
	 * @return the entry as a scan applies it
	 */
	public BetterleaksAllowlistEntry toEntry() {
		return new BetterleaksAllowlistEntry(scope, repoName, pathGlob, ruleId);
	}
}
