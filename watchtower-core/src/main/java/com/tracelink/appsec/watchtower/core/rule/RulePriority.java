package com.tracelink.appsec.watchtower.core.rule;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

/**
 * Represents the priority of a rule, regardless of rule type. Each rule is assigned a priority from
 * 1 to 5, with 1 being the highest priority and 5 being the lowest priority. High priority rules
 * indicate that violations should be addressed immediately, whereas low priority rules might be
 * best practices or suggestions.
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
	 * {@link RulePriority#getPriority()}. If the number is an invalid value, then
	 * {@link RulePriority#LOW} will be returned.
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

	/**
	 * Get the priority which corresponds to the given name as returned by
	 * {@link RulePriority#getName()}.
	 *
	 * @param name the numeric priority value
	 * @return the RulePriority associated with the given priority name, or null
	 */
	public static RulePriority priorityForName(String name) {
		for (RulePriority priority : RulePriority.values()) {
			if (priority.getName().equals(name)) {
				return priority;
			}
		}
		return null;
	}


	/**
	 * Attribute Converter to manage translating between database-stored values and Java Objects
	 * 
	 * @author csmith
	 *
	 */
	@Converter
	public static class RulePriorityConverter implements AttributeConverter<RulePriority, String> {

		@Override
		public String convertToDatabaseColumn(RulePriority attribute) {
			return attribute.getName();
		}

		@Override
		public RulePriority convertToEntityAttribute(String dbData) {
			return RulePriority.priorityForName(dbData);
		}

	}
}
