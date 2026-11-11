package com.tracelink.appsec.module.betterleaks.engine;

/**
 * The outcome of running a custom rule against its own samples with the real binary.
 *
 * @param matchesPositive whether it found the positive sample
 * @param matchesNegative whether it found the negative sample
 * @param problem         why the rule could not be tested (e.g. an invalid regex), or null
 * @author Watchtower
 */
public record BetterleaksRuleTestResult(boolean matchesPositive, boolean matchesNegative,
		String problem) {

	/**
	 * @param problem why the rule could not be tested
	 * @return a failed result
	 */
	public static BetterleaksRuleTestResult problem(String problem) {
		return new BetterleaksRuleTestResult(false, false, problem);
	}

	/**
	 * @return true if the rule ran, matched its positive sample and did not match its negative
	 */
	public boolean passed() {
		return problem == null && matchesPositive && !matchesNegative;
	}

	/**
	 * @return a user-facing explanation of why the rule did not pass, or null if it passed
	 */
	public String failureReason() {
		if (problem != null) {
			return problem;
		}
		if (!matchesPositive) {
			return "The rule does not match its positive sample.";
		}
		if (matchesNegative) {
			return "The rule also matches its negative sample.";
		}
		return null;
	}
}
