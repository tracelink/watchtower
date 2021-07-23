package com.tracelink.appsec.watchtower.core.ruleset;

/**
 * Represents the designation of a ruleset.
 *
 * @author mcool
 */
public enum RulesetDesignation {
	/**
	 * The default ruleset is a special case of a primary ruleset, and is automatically assigned to
	 * all new repositories that are added to Watchtower.
	 */
	DEFAULT("Default"),
	/**
	 * Primary rulesets can be assigned to repositories and can inherit from other Primary rulesets
	 * or Supporting or Provided rulesets
	 */
	PRIMARY("Primary"),
	/**
	 * Supporting rulesets can only inherit from other Supporting or Provided rulesets
	 */
	SUPPORTING("Supporting"),
	/**
	 * Provided rulesets are automatically built from 3rd party scanners and are immutable inside of
	 * Watchtower
	 */
	PROVIDED("Provided");

	RulesetDesignation(String name) {
		this.name = name;
	}

	private String name;

	public String getName() {
		return name;
	}
}
