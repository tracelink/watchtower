package com.tracelink.appsec.watchtower.core.ruleset;

/**
 * Represents the designation of a ruleset. Primary rulesets can be assigned to
 * repositories and can inherit from both primary and supporting rulesets.
 * Supporting rulesets can only inherit from other supporting rulesets. The
 * default ruleset is a special case of a primary ruleset, and is automatically
 * assigned to all new repositories that are added to Watchtower.
 *
 * @author mcool
 */
public enum RulesetDesignation {
	DEFAULT("Default"), PRIMARY("Primary"), SUPPORTING("Supporting");

	RulesetDesignation(String name) {
		this.name = name;
	}

	private String name;

	public String getName() {
		return name;
	}
}
