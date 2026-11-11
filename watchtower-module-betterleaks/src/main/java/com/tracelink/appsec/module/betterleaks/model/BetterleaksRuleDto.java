package com.tracelink.appsec.module.betterleaks.model;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleExecutionIdentity;

/**
 * What the scanner needs from any Betterleaks rule, provided or custom.
 *
 * @author Watchtower
 */
public interface BetterleaksRuleDto {
	RuleExecutionIdentity getExecutionIdentity();

	/** Prefix of every Betterleaks rule's Watchtower name. */
	String NAME_PREFIX = "Betterleaks: ";

	/**
	 * @return the id Betterleaks knows the rule by
	 */
	String getBetterleaksId();

	/**
	 * @return the Watchtower rule name, {@code "Betterleaks: <id>"}
	 */
	String getName();

	RulePriority getPriority();

	String getMessage();

	BetterleaksCategory getCategory();
}
