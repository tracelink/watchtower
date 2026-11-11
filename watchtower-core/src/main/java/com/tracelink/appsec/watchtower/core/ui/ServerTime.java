package com.tracelink.appsec.watchtower.core.ui;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;

/**
 * Converts the server's wall-clock times back to epoch milliseconds for the browser
 * (localizetime.js shows them in the viewer's zone).
 *
 * <p>Every LocalDateTime in Watchtower is created in the server's zone ({@code LocalDateTime.now()},
 * {@code ofInstant(..., ZoneId.systemDefault())}). Converting one back as if it were UTC shifted
 * every time by the server's offset: on Dev (+05:30) a PR finished at 21:10 showed as 02:40 the
 * next day on the results page while Home showed 21:10 (UAT #9).
 */
public final class ServerTime {

	private ServerTime() { }

	/** @return epoch milliseconds, or 0 when the time was never recorded */
	public static long toEpochMillis(LocalDateTime serverTime) {
		return serverTime == null ? 0L
				: serverTime.atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
	}

	/** @return epoch milliseconds of the start of that day in the server's zone */
	public static long startOfDayMillis(LocalDate serverDate) {
		return serverDate.atStartOfDay(ZoneId.systemDefault()).toInstant().toEpochMilli();
	}
}
