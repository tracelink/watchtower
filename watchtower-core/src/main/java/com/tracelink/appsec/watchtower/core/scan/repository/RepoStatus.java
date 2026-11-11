package com.tracelink.appsec.watchtower.core.scan.repository;

import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;

/**
 * The one status chip a repository shows, computed from its row (almost nothing stored). The
 * first matching state wins, in declaration order.
 *
 * @author Watchtower
 */
public enum RepoStatus {
	/** Its integration was deleted. */
	ORPHANED("Orphaned", "danger"),
	/** Not in the last complete sync, or the SCM said it does not exist. */
	GONE("Gone", "danger"),
	/** A person paused scanning: pull requests are not scanned and plans skip it. */
	PAUSED("Paused", "warning"),
	/** It has had pull requests, but none recently. */
	INACTIVE("No recent PRs", "neutral"),
	ACTIVE("Active", "success");

	private final String label;

	private final String tone;

	RepoStatus(String label, String tone) {
		this.label = label;
		this.tone = tone;
	}

	/** Image repositories have image scans, not pull requests (UAT #36). */
	public String labelFor(boolean image) {
		return image && this == INACTIVE ? "No recent image scans" : label;
	}

	public String getLabel() {
		return label;
	}

	public String getTone() {
		return tone;
	}

	/** @return the lower-case name used in URLs, e.g. {@code inactive} */
	public String getKey() {
		return name().toLowerCase(Locale.ROOT);
	}

	/**
	 * @param key a status key from a URL, any case; blank or unknown means no status filter
	 * @return the status
	 */
	public static Optional<RepoStatus> fromKey(String key) {
		return Arrays.stream(values()).filter(s -> s.name().equalsIgnoreCase(
				key == null ? "" : key.trim())).findFirst();
	}
}
