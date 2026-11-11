package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result;

import java.time.Duration;

/**
 * Which pull request scans the results page lists: the last {@value #RECENT_DAYS} days (the
 * default, so the page reads an indexed window instead of every scan ever run) or the older
 * ones. Nothing is moved or deleted.
 *
 * @author Watchtower
 */
public enum PRResultPeriod {

	RECENT("recent", "Last 90 days"),
	//
	OLDER("older", "Older");

	public static final int RECENT_DAYS = 90;

	private final String key;

	private final String display;

	PRResultPeriod(String key, String display) {
		this.key = key;
		this.display = display;
	}

	public String getKey() {
		return key;
	}

	public String getDisplay() {
		return display;
	}

	/**
	 * @param now the current time, epoch millis
	 * @return the epoch millis where the recent window starts
	 */
	public static long cutoff(long now) {
		return now - Duration.ofDays(RECENT_DAYS).toMillis();
	}

	/**
	 * @param key a period's key
	 * @return that period; {@link #RECENT} for anything else
	 */
	public static PRResultPeriod of(String key) {
		return OLDER.key.equals(key) ? OLDER : RECENT;
	}
}
