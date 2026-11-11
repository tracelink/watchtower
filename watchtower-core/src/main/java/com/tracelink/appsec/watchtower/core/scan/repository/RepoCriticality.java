package com.tracelink.appsec.watchtower.core.scan.repository;

/**
 * How important a repository is to the business. Lower levels are scanned first when many
 * repositories are queued at once.
 *
 * @author Watchtower
 */
public enum RepoCriticality {
	CRITICAL(1, "Critical"), HIGH(2, "High"), NORMAL(3, "Normal"), LOW(4, "Low");

	private final int level;
	private final String displayName;

	RepoCriticality(int level, String displayName) {
		this.level = level;
		this.displayName = displayName;
	}

	public int getLevel() {
		return level;
	}

	public String getDisplayName() {
		return displayName;
	}

	/**
	 * @param level a stored level
	 * @return the matching criticality
	 * @throws IllegalArgumentException if the level is not 1-4
	 */
	public static RepoCriticality of(int level) {
		for (RepoCriticality value : values()) {
			if (value.level == level) {
				return value;
			}
		}
		throw new IllegalArgumentException("Criticality must be 1 (Critical) to 4 (Low)");
	}
}
