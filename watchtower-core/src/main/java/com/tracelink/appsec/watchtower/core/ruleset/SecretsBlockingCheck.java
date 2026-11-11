package com.tracelink.appsec.watchtower.core.ruleset;

import java.util.function.Predicate;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/**
 * Spots a ruleset whose blocking level lets detected secrets through. Secrets rules start as low
 * as {@link RulePriority#MEDIUM} (generic secrets), so a ruleset that blocks only at a higher
 * level, or never blocks, reports them without ever blocking the pull request. That is the
 * ruleset owner's choice to make; the ruleset page just makes it visible.
 *
 * @author Watchtower
 */
public final class SecretsBlockingCheck {

	private SecretsBlockingCheck() {
	}

	/**
	 * @param ruleset           the ruleset, with its inherited rulesets
	 * @param isSensitiveModule whether a module name belongs to a secrets scanner
	 * @return true if the ruleset, or a ruleset it inherits, has secrets rules and its blocking
	 *         level would not block a MEDIUM finding
	 */
	public static boolean shouldWarn(RulesetDto ruleset, Predicate<String> isSensitiveModule) {
		if (ruleset == null) {
			return false;
		}
		RulePriority blockingLevel = ruleset.getBlockingLevel();
		boolean blocksMedium =
				blockingLevel != null && RulePriority.MEDIUM.compareTo(blockingLevel) <= 0;
		if (blocksMedium) {
			return false;
		}
		return ruleset.getAllRules().stream()
				.anyMatch(rule -> isSensitiveModule.test(rule.getModule()));
	}
}
