package com.tracelink.appsec.watchtower.core.scan.repository;

import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;

/**
 * Whether a repository scan has covered a repository lately, judged by its latest finished scan
 * ({@code repositories.last_repo_scan_id}). Used by the dashboard's coverage boxes, which link
 * to the inventory filtered the same way.
 *
 * @author Watchtower
 */
public enum RepoCoverage {
	/** Its latest repository scan ended within {@link #WINDOW_DAYS} days. */
	RECENT("Scanned in the last 30 days"),
	/** Scanned before, but not within {@link #WINDOW_DAYS} days. */
	STALE("Not scanned in 30 days"),
	/** Never scanned by a repository scan. */
	NEVER("Never scanned");

	public static final int WINDOW_DAYS = 30;

	private final String label;

	RepoCoverage(String label) {
		this.label = label;
	}

	public String getLabel() {
		return label;
	}

	public String getKey() {
		return name().toLowerCase(Locale.ROOT);
	}

	/**
	 * @param key a key from a URL, any case; blank or unknown means no coverage filter
	 * @return the coverage
	 */
	public static Optional<RepoCoverage> fromKey(String key) {
		return Arrays.stream(values()).filter(c -> c.name().equalsIgnoreCase(
				key == null ? "" : key.trim())).findFirst();
	}
}
