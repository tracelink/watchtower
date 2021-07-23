package com.tracelink.appsec.watchtower.core.ruleset;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.OrderBy;
import javax.persistence.Table;

import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/**
 * Entity description for the ruleset entity. Holds name and description, as well as a list of rules
 * contained in this ruleset and a list of rulesets from which to inherit rules.
 *
 * @author mcool
 */
@Entity
@Table(name = "rulesets")
public class RulesetEntity {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "ruleset_id")
	private long id;

	@ManyToMany(fetch = FetchType.EAGER)
	@JoinTable(name = "ruleset_ruleset", joinColumns = @JoinColumn(name = "ruleset_id"),
			inverseJoinColumns = @JoinColumn(name = "inherited_ruleset_id"))
	private Set<RulesetEntity> rulesets = new HashSet<>();

	@ManyToMany(fetch = FetchType.EAGER)
	@JoinTable(name = "rule_ruleset", joinColumns = @JoinColumn(name = "ruleset_id"),
			inverseJoinColumns = @JoinColumn(name = "rule_id"))
	@OrderBy("name asc")
	private Set<RuleEntity> rules = new HashSet<>();

	@Column(name = "name")
	private String name;

	@Column(name = "description")
	private String description;

	@Column(name = "designation")
	@Enumerated(EnumType.STRING)
	private RulesetDesignation designation;

	@Column(name = "blocking_level")
	@Enumerated(EnumType.ORDINAL)
	private RulePriority blockingLevel;

	public long getId() {
		return id;
	}

	public void setId(long id) {
		this.id = id;
	}

	public Set<RulesetEntity> getRulesets() {
		return rulesets;
	}

	public void setRulesets(Set<RulesetEntity> rulesets) {
		this.rulesets = rulesets;
	}

	public Set<RuleEntity> getRules() {
		return rules;
	}

	public void setRules(Set<RuleEntity> rules) {
		this.rules = rules;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public RulesetDesignation getDesignation() {
		return designation;
	}

	public void setDesignation(RulesetDesignation designation) {
		this.designation = designation;
	}

	public RulePriority getBlockingLevel() {
		return blockingLevel;
	}

	public void setBlockingLevel(RulePriority blockingLevel) {
		this.blockingLevel = blockingLevel;
	}

	/**
	 * Determines if the given ruleset is inherited by this ruleset, either directly or recursively.
	 *
	 * @param ruleset the ruleset that may be inherited from
	 * @return true if the given ruleset is inherited by this ruleset, false otherwise
	 */
	public boolean containsRuleset(RulesetEntity ruleset) {
		return rulesets.contains(ruleset)
				|| rulesets.stream().anyMatch(r -> r.containsRuleset(ruleset));
	}

	/**
	 * Converts this database entity object into a data transfer object that is more convenient in
	 * UI and other operations. Converts all contained rules and rulesets to DTOs.
	 *
	 * @return ruleset DTO representing this ruleset entity
	 */
	public RulesetDto toDto() {
		RulesetDto dto = new RulesetDto();
		dto.setId(getId());
		dto.setName(getName());
		dto.setDescription(getDescription());
		dto.setDesignation(getDesignation());
		dto.setBlockingLevel(getBlockingLevel());
		dto.setRulesets(
				getRulesets().stream().map(RulesetEntity::toDto).collect(Collectors.toSet()));
		dto.setRules(getRules().stream().map(RuleEntity::toDto).collect(Collectors.toSet()));
		return dto;
	}
}
