package com.tracelink.appsec.watchtower.core.rule;

import java.time.LocalDate;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;

/** Source-free, installation-local rule metadata, independent of exported engine definitions. */
@Embeddable
public class RuleStewardship {
	/** The one value {@code securityRelevance} takes besides null. */
	public static final String NOT_SECURITY = "NOT_SECURITY";

	@Enumerated(EnumType.STRING)
	@Column(name = "rule_state", nullable = false, length = 16)
	private RuleState state = RuleState.ACTIVE;
	@Column(name = "rule_owner", length = 255)
	private String owner;
	@Column(name = "review_by")
	private LocalDate reviewBy;
	@Column(name = "cwe", length = 32)
	private String cwe;
	/** Further CWEs the rule also covers, comma separated ({@code CWE-564,CWE-89}); the primary one is {@link #cwe}. */
	@Column(name = "secondary_cwes", length = 160)
	private String secondaryCwes;
	/** {@link #NOT_SECURITY} for a style or quality rule that has no CWE by design; otherwise null. */
	@Column(name = "security_relevance", length = 16)
	private String securityRelevance;
	@Column(name = "stewardship_category", length = 128)
	private String category;
	@Column(name = "origin", length = 255)
	private String origin;
	@Column(name = "origin_key", length = 255)
	private String originKey;
	@Column(name = "rule_revision", length = 64)
	private String revision;
	@Column(name = "created_at")
	private Long createdAt;
	/**
	 * Set when a provided rule arrived with an upstream upgrade (R5.4): it runs and reports, but never
	 * blocks until approved. Installation-local, so it is never exported or part of a definition.
	 */
	@Column(name = "upstream_hold_since")
	private Long upstreamHoldSince;
	@Column(name = "updated_at")
	private Long updatedAt;

	public RuleState getState() { return state; }
	public void setState(RuleState state) { this.state = state; }
	public String getOwner() { return owner; }
	public void setOwner(String owner) { this.owner = owner; }
	public LocalDate getReviewBy() { return reviewBy; }
	public void setReviewBy(LocalDate reviewBy) { this.reviewBy = reviewBy; }
	public String getCwe() { return cwe; }
	public void setCwe(String cwe) { this.cwe = cwe; }
	public String getSecondaryCwes() { return secondaryCwes; }
	public void setSecondaryCwes(String secondaryCwes) { this.secondaryCwes = secondaryCwes; }
	public String getSecurityRelevance() { return securityRelevance; }
	public void setSecurityRelevance(String securityRelevance) { this.securityRelevance = securityRelevance; }
	@com.fasterxml.jackson.annotation.JsonIgnore
	public boolean isNotSecurity() { return NOT_SECURITY.equals(securityRelevance); }
	public String getCategory() { return category; }
	public void setCategory(String category) { this.category = category; }
	public String getOrigin() { return origin; }
	public void setOrigin(String origin) { this.origin = origin; }
	public String getOriginKey() { return originKey; }
	public void setOriginKey(String originKey) { this.originKey = originKey; }
	public String getRevision() { return revision; }
	public void setRevision(String revision) { this.revision = revision; }
	public Long getCreatedAt() { return createdAt; }
	public void setCreatedAt(Long createdAt) { this.createdAt = createdAt; }
	public Long getUpdatedAt() { return updatedAt; }
	@com.fasterxml.jackson.annotation.JsonIgnore
	public Long getUpstreamHoldSince() { return upstreamHoldSince; }
	@com.fasterxml.jackson.annotation.JsonIgnore
	public void setUpstreamHoldSince(Long upstreamHoldSince) { this.upstreamHoldSince = upstreamHoldSince; }
	@com.fasterxml.jackson.annotation.JsonIgnore
	public boolean isUpstreamHeld() { return upstreamHoldSince != null; }
	public void setUpdatedAt(Long updatedAt) { this.updatedAt = updatedAt; }

	public RuleStewardship copy() {
		RuleStewardship copy = new RuleStewardship();
		copy.state = state;
		copy.owner = owner;
		copy.reviewBy = reviewBy;
		copy.cwe = cwe;
		copy.secondaryCwes = secondaryCwes;
		copy.securityRelevance = securityRelevance;
		copy.category = category;
		copy.origin = origin;
		copy.originKey = originKey;
		copy.revision = revision;
		copy.createdAt = createdAt;
		copy.updatedAt = updatedAt;
		copy.upstreamHoldSince = upstreamHoldSince;
		return copy;
	}
}
