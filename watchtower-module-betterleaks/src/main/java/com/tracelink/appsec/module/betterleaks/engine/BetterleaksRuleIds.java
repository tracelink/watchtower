package com.tracelink.appsec.module.betterleaks.engine;

import java.util.regex.Pattern;

/**
 * The shape of a Betterleaks rule id. Ids reach the command line and the generated config, so
 * anything outside lower-case slugs - which could read as a flag, a list separator or TOML - is
 * refused everywhere.
 *
 * @author Watchtower
 */
public final class BetterleaksRuleIds {

	private static final Pattern RULE_ID = Pattern.compile("[a-z0-9][a-z0-9._-]{0,99}");

	/** Every custom rule id starts with this; built-in ids never do. */
	public static final String CUSTOM_PREFIX = "custom-";

	/**
	 * @param ruleId a rule id
	 * @return true if it names a Watchtower custom rule rather than a built-in one
	 */
	public static boolean isCustom(String ruleId) {
		return ruleId != null && ruleId.startsWith(CUSTOM_PREFIX);
	}

	private BetterleaksRuleIds() {
	}

	/**
	 * @param ruleId a candidate rule id
	 * @return true if it is a well-formed Betterleaks rule id
	 */
	public static boolean isValid(String ruleId) {
		return ruleId != null && RULE_ID.matcher(ruleId).matches();
	}
}
