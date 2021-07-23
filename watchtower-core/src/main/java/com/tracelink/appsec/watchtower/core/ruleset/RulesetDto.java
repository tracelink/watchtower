package com.tracelink.appsec.watchtower.core.ruleset;


import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Collectors;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/**
 * Represents the data transfer object for the {@link RulesetEntity}. All rules and rulesets
 * contained in the entity are converted to DTOs. This class also contains some convenience methods
 * used in the UI.
 *
 * @author mcool
 */
public class RulesetDto implements Comparable<RulesetDto> {
	private static final String CANNOT_BE_NULL = " cannot be null.";
	private static final String CANNOT_BE_EMPTY = " cannot be empty.";

	@NotNull(message = "Rule ID" + CANNOT_BE_NULL)
	private Long id;

	@NotNull(message = "Name" + CANNOT_BE_NULL)
	@NotEmpty(message = "Name" + CANNOT_BE_EMPTY)
	@Size(max = 100, message = "Name cannot have a length of more than 100 characters.")
	private String name;

	@NotNull(message = "Description" + CANNOT_BE_NULL)
	@NotEmpty(message = "Description" + CANNOT_BE_EMPTY)
	@Size(max = 255, message = "Description cannot have a length of more than 256 characters.")
	private String description;

	@NotNull(message = "Designation" + CANNOT_BE_NULL)
	private RulesetDesignation designation;

	private RulePriority blockingLevel;

	private Set<RulesetDto> rulesets = new HashSet<>();
	private Set<RuleDto> rules = new HashSet<>();

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

	public Set<RulesetDto> getRulesets() {
		return rulesets;
	}

	public void setRulesets(Set<RulesetDto> rulesets) {
		this.rulesets = rulesets;
	}

	public Set<RuleDto> getRules() {
		return new TreeSet<>(rules);
	}

	public void setRules(Set<RuleDto> rules) {
		this.rules = rules;
	}

	/**
	 * Determines whether this ruleset is the default ruleset.
	 *
	 * @return true if this ruleset has the default designation, false otherwise
	 */
	public boolean isDefault() {
		return designation.equals(RulesetDesignation.DEFAULT);
	}

	/**
	 * Determines whether this ruleset is a supporting ruleset.
	 *
	 * @return true if this ruleset has the supporting designation, false otherwise
	 */
	public boolean isSupporting() {
		return designation.equals(RulesetDesignation.SUPPORTING);
	}

	/**
	 * Determines whether this ruleset is a provided ruleset.
	 *
	 * @return true if this ruleset has the provided designation, false otherwise
	 */
	public boolean isProvided() {
		return designation.equals(RulesetDesignation.PROVIDED);
	}

	/**
	 * Gets the number of unique rules in this ruleset, including inherited rules.
	 *
	 * @return number of unique rules in this ruleset
	 */
	public int getNumRules() {
		return getAllRules().size();
	}

	/**
	 * Gets a map of all inherited rules. The key is the rule DTO and the value is the name of the
	 * ruleset it is inherited from.
	 *
	 * @return map from rule to ruleset it is inherited from
	 */
	public Map<RuleDto, String> getInheritedRules() {
		Map<RuleDto, String> inheritedRules = new TreeMap<>();
		for (RulesetDto ruleset : rulesets) {
			ruleset.getRules().forEach(rule -> inheritedRules.put(rule, ruleset.getName()));
			inheritedRules.putAll(ruleset.getInheritedRules());
		}
		return inheritedRules;
	}

	/**
	 * Gets a list of IDs of the rules directly contained in this ruleset.
	 *
	 * @return a list of IDs to rules in this ruleset
	 */
	public Set<Long> getRuleIds() {
		return rules.stream().map(RuleDto::getId).collect(Collectors.toSet());
	}

	@Override
	public int compareTo(RulesetDto o) {
		int designationCompare = getDesignation().compareTo(o.getDesignation());
		return designationCompare == 0 ? getName().compareTo(o.getName()) : designationCompare;
	}

	/**
	 * Gets a set of all rules contained in this ruleset, including those that are inherited from
	 * other rulesets.
	 *
	 * @return set of all rules in this ruleset
	 */
	public Set<RuleDto> getAllRules() {
		Set<RuleDto> allRules = new TreeSet<>(rules);
		for (RulesetDto ruleset : rulesets) {
			allRules.addAll(ruleset.getAllRules());
		}
		return allRules;
	}
}
