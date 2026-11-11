package com.tracelink.appsec.watchtower.core.rule;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

/**
 * Represents the priority of a rule, regardless of rule type. Each rule is assigned a priority from
 * 1 to 6, with 1 being the highest priority and 6 being the lowest priority. High priority rules
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
	LOW(5, "Low"),
	INFORMATIONAL(6, "Informational");

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

	/** The short label for buttons ("Med-high", "Info"); the full name stays {@link #getName()}. */
	public String getShortName() {
		return switch (this) {
			case MEDIUM_HIGH -> "Med-high";
			case MEDIUM_LOW -> "Med-low";
			case INFORMATIONAL -> "Info";
			default -> name;
		};
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
			return attribute == null ? null : attribute.getName();
		}

		@Override
		public RulePriority convertToEntityAttribute(String dbData) {
			return RulePriority.priorityForName(dbData);
		}

	}

	/**
	 * Stores a priority as its number (1 = {@link #HIGH} … 6 = {@link #INFORMATIONAL}) for numeric
	 * columns; null stays null.
	 */
	@Converter
	public static class RulePriorityNumberConverter
			implements AttributeConverter<RulePriority, Integer> {

		@Override
		public Integer convertToDatabaseColumn(RulePriority attribute) {
			return attribute == null ? null : attribute.getPriority();
		}

		@Override
		public RulePriority convertToEntityAttribute(Integer dbData) {
			return dbData == null ? null : RulePriority.valueOf(dbData.intValue());
		}
	}
}
