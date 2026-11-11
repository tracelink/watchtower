package com.tracelink.appsec.watchtower.core.scan.presentation;

import java.util.Locale;

/**
 * The one way a span of a minute or more reads in Watchtower: "10m 12s". Lists, reports, dashboards and the AWS
 * dialog all call this, so the same span never reads as "10.20 mins" in one place and "10m 12s" in another.
 */
public final class DurationText {
	private static final long MILLIS_PER_SECOND = 1_000L;
	private static final long MILLIS_PER_MINUTE = 60_000L;

	private DurationText() {
	}

	/** "850 ms", "8.00 s" or "10m 12s"; a negative span is "Not recorded". */
	public static String of(double millis) {
		if (millis < 0) {
			return "Not recorded";
		}
		if (millis < MILLIS_PER_SECOND) {
			return String.format(Locale.ROOT, "%.0f ms", millis);
		}
		if (millis < MILLIS_PER_MINUTE) {
			return String.format(Locale.ROOT, "%.2f s", millis / MILLIS_PER_SECOND);
		}
		return minutesAndSeconds((long) millis);
	}

	/** A span of any length as whole minutes and seconds: 612_000 is "10m 12s". */
	public static String minutesAndSeconds(long millis) {
		return millis / MILLIS_PER_MINUTE + "m " + (millis % MILLIS_PER_MINUTE) / MILLIS_PER_SECOND + "s";
	}
}
