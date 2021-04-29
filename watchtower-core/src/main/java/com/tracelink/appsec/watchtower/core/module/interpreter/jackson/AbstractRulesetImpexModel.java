package com.tracelink.appsec.watchtower.core.module.interpreter.jackson;

import java.util.Set;

/**
 * Representation of a ruleset that facilitates translation to and from structured data.
 * Implementations of this class will be deserialized and serialized in order to import and export
 * rulesets.
 *
 * @author mcool
 */
public abstract class AbstractRulesetImpexModel {
	/**
	 * Gets the name of this ruleset.
	 *
	 * @return ruleset name
	 */
	public abstract String getName();

	/**
	 * Gets the description of this ruleset.
	 *
	 * @return ruleset description
	 */
	public abstract String getDescription();

	/**
	 * Gets the list of rules contained in this ruleset.
	 *
	 * @return list of rules in this ruleset
	 */
	public abstract Set<? extends AbstractRuleImpexModel> getRules();
}
