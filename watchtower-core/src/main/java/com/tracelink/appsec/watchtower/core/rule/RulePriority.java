package com.tracelink.appsec.watchtower.core.rule;

/**
 * Represents the priority of a rule, regardless of rule type. Each rule is assigned a priority from 1 to 5, with 1
 * being the highest priority and 5 being the lowest priority. High priority rules indicate that violations should be
 * addressed immediately, whereas low priority rules might be best practices or suggestions.
 *
 * @author mcool
 */
public enum RulePriority {
	HIGH(1, "High"),
	MEDIUM_HIGH(2, "Medium High"),
	MEDIUM(3, "Medium"),
	MEDIUM_LOW(4, "Medium Low"),
	LOW(5, "Low");

	private final int priority;
	private final String name;

	RulePriority(int priority, String name) {
		this.priority = priority;
		this.name = name;
	}

	public int getPriority() {
		return priority;
	}

	public String getName() {
		return name;
	}

	/**
	 * Get the priority which corresponds to the given number as returned by
	 * {@link RulePriority#getPriority()}. If the number is an invalid value,
	 * then {@link RulePriority#LOW} will be returned.
	 *
	 * @param priority the numeric priority value
	 * @return the RulePriority associated with the given priority value
	 */
	public static RulePriority valueOf(int priority) {
		try {
			return RulePriority.values()[priority - 1];
		} catch (ArrayIndexOutOfBoundsException e) {
			return LOW;
		}
	}
}
