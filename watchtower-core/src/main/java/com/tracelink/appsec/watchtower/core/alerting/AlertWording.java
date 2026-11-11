package com.tracelink.appsec.watchtower.core.alerting;

import java.util.Locale;

/**
 * Plain words for the Alert settings page (UAT walkthrough, 2026-10-16): alert keys as names with
 * an icon, repeat windows in days ("No repeats for 30 days", not "720 h") and how long a delivery
 * took ("Sent · 4 s").
 *
 * @author Watchtower
 */
public final class AlertWording {

	private static final int HOURS_PER_DAY = 24;

	private static final long SECOND = 1000L;

	private static final long MINUTE = 60 * SECOND;

	private static final long HOUR = 60 * MINUTE;

	private AlertWording() {
	}

	/**
	 * @param key an alert key such as {@code SECRET_DETECTED}, or its label "Secret detected"
	 * @return the key as a sentence-case name, e.g. "Secret detected"
	 */
	public static String name(String key) {
		if (key == null || key.isBlank()) {
			return "";
		}
		// PR is an acronym, so it stays upper case inside the sentence-case name.
		String text = key.replace('_', ' ').toLowerCase(Locale.ROOT).replaceAll("\\bpr\\b", "PR");
		return Character.toUpperCase(text.charAt(0)) + text.substring(1);
	}

	/**
	 * @param key an alert key or its label
	 * @return a Material icon for the kind of alert
	 */
	public static String icon(String key) {
		String text = key == null ? "" : key.toLowerCase(Locale.ROOT);
		if (text.contains("secret")) {
			return "key";
		}
		if (text.contains("scanner") || text.contains("fail")) {
			return "error_outline";
		}
		return "notifications";
	}

	/**
	 * @param hours a repeat window in hours
	 * @return "1 day", "30 days" for whole days, otherwise "36 hours"
	 */
	public static String window(int hours) {
		if (hours > 0 && hours % HOURS_PER_DAY == 0) {
			int days = hours / HOURS_PER_DAY;
			return days + (days == 1 ? " day" : " days");
		}
		return hours + (hours == 1 ? " hour" : " hours");
	}

	/**
	 * @param createdAt when the alert was raised, epoch millis
	 * @param sentAt    when it was delivered, epoch millis, or null
	 * @return how long delivery took, e.g. "4 s", "3 min", "2 h"; empty when not delivered
	 */
	public static String lag(long createdAt, Long sentAt) {
		if (sentAt == null) {
			return "";
		}
		long took = Math.max(0, sentAt - createdAt);
		if (took < MINUTE) {
			return Math.round((double) took / SECOND) + " s";
		}
		if (took < HOUR) {
			return Math.round((double) took / MINUTE) + " min";
		}
		return Math.round((double) took / HOUR) + " h";
	}
}
