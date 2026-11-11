package com.tracelink.appsec.watchtower.core.rule;

import java.util.Set;
import java.util.TreeSet;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

/**
 * Represents a data transfer object for the {@link RuleEntity}. All fields in this object are in
 * plain text. Contains the fields inherited by all rule DTOs, regardless of type.
 * <p>
 * Note To Implementors: This Dto is used throughout Watchtower to transfer between Import/Export
 * items, Scanners, Rule Entities, etc so it must contain the superset of all data needed for each.
 * Additionally, as this is used for Import/Export, you may need to configure fields and/or methods
 * with the {@linkplain JsonIgnore} annotation.
 *
 * @author mcool
 */
public abstract class RuleDto implements Comparable<RuleDto> {
	protected static final String CANNOT_BE_NULL = " cannot be null.";
	protected static final String CANNOT_BE_EMPTY = " cannot be empty.";
	private Long id;
	private RuleStewardship stewardship = new RuleStewardship();

	@JsonIgnore
	public RuleStewardship getStewardship() { return stewardship; }

	@JsonIgnore
	public void setStewardship(RuleStewardship stewardship) { this.stewardship = stewardship; }

	@JsonIgnore
	public boolean isRetired() { return stewardship.getState() == RuleState.RETIRED; }

	/** Current managed definition only; this must never backfill a historical finding revision. */
	@JsonIgnore
	public final String getRevision() {
		RuleRevision definition = executableDefinition();
		return definition == null ? null : definition.hash();
	}

	@JsonIgnore
	public final RuleExecutionIdentity getExecutionIdentity() {
		return new RuleExecutionIdentity(id == null || id <= 0 ? null : id, getModule(),
				getRevision(), getExternalRuleKey(), stewardship.getOriginKey());
	}

	@JsonIgnore
	public String getExternalRuleKey() { return null; }

	/** Modules opt in explicitly; an unsupported definition remains unknown. */
	protected RuleRevision executableDefinition() { return null; }

	protected final RuleRevision newDefinition() {
		return RuleRevision.definition(getModule(), getRuleDesignation().name())
				.field("message", getMessage());
	}

	@NotNull(message = "Name" + CANNOT_BE_NULL)
	@NotEmpty(message = "Name" + CANNOT_BE_EMPTY)
	@Size(max = 100, message = "Name cannot have a length of more than 100 characters.")
	private String name;

	@NotNull(message = "Priority" + CANNOT_BE_NULL)
	private RulePriority priority;

	private Set<String> rulesets = new TreeSet<>();

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public RulePriority getPriority() {
		return priority;
	}

	public void setPriority(RulePriority priority) {
		this.priority = priority;
	}

	public Set<String> getRulesets() {
		return rulesets;
	}

	public void setRulesets(Set<String> rulesets) {
		this.rulesets = rulesets;
	}

	@Override
	public int compareTo(RuleDto o) {
		return getName().compareTo(o.getName());
	}

	/**
	 * Consistent with {@link #compareTo(RuleDto)} - both key on {@link #getName()}, since rule
	 * name is this application's effective unique identifier for a rule (enforced at import time
	 * via {@code RuleRepository.findByName}, not by a database constraint). Needed so that
	 * {@code Set<RuleDto>}-based deduplication (e.g. {@link RulesetDto#getAllRules()}) actually
	 * collapses the same rule reached through more than one ruleset-inheritance path, instead of
	 * relying on the default identity-based equality.
	 */
	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof RuleDto)) {
			return false;
		}
		return getName() != null && getName().equals(((RuleDto) o).getName());
	}

	@Override
	public int hashCode() {
		return getName() == null ? 0 : getName().hashCode();
	}

	@Override
	public String toString() {
		return getName();
	}

	@JsonIgnore
	public final boolean isCustom() {
		return RuleDesignation.CUSTOM.equals(getRuleDesignation());
	}

	@JsonIgnore
	public final boolean isProvided() {
		return RuleDesignation.PROVIDED.equals(getRuleDesignation());
	}

	/**
	 * This returns the name of the module that the rule is associated with.
	 *
	 * @return module name, representing the rule type
	 */
	@JsonIgnore
	public abstract String getModule();

	public abstract String getAuthor();

	public abstract String getMessage();

	public abstract String getExternalUrl();

	public abstract RuleDesignation getRuleDesignation();

	/**
	 * Converts this data transfer object into a database entity object. Used to help import rules
	 * to the database.
	 *
	 * @return database entity object representing this rule DTO
	 */
	public abstract RuleEntity toEntity();
}
