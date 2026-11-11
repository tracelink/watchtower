package com.tracelink.appsec.watchtower.core.logging;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * One line of the in-memory log, split so the Logs page can show the level as a chip and the
 * logger by its short class name (UAT walkthrough, 2026-10-16). The text comes from
 * {@link LogsService}'s pattern ({@code date time logger level - message}); a line in any other
 * shape keeps its whole text as the message and has no level.
 *
 * @param time    the time of day ("13:58:36"), or empty when the line could not be split
 * @param date    the date ("2026-10-16"), or empty
 * @param level   TRACE, DEBUG, INFO, WARN or ERROR, or empty
 * @param logger  the logger as printed (possibly abbreviated, e.g. "c.t.a.w.c.s.a.Foo")
 * @param message the message, including any stack trace lines
 */
public record LogLine(String time, String date, String level, String logger, String message) {

	private static final Pattern LINE = Pattern.compile(
			"^(\\d{4}-\\d{2}-\\d{2}) (\\d{2}:\\d{2}:\\d{2})(?:\\.\\d+)? (\\S+)\\s+"
					+ "(TRACE|DEBUG|INFO|WARN|ERROR)\\s+- (.*)$",
			Pattern.DOTALL);

	/**
	 * Split one formatted log line.
	 *
	 * @param raw the formatted line
	 * @return the parts; an unrecognised line keeps its text as the message
	 */
	public static LogLine parse(String raw) {
		String text = raw == null ? "" : raw.stripTrailing();
		Matcher matcher = LINE.matcher(text);
		if (!matcher.matches()) {
			return new LogLine("", "", "", "", text);
		}
		return new LogLine(matcher.group(2), matcher.group(1), matcher.group(4), matcher.group(3),
				matcher.group(5));
	}

	/**
	 * @return the class name without its package ("IntegrationHealthService")
	 */
	public String shortLogger() {
		int dot = logger.lastIndexOf('.');
		return dot < 0 ? logger : logger.substring(dot + 1);
	}

	/**
	 * @return the level in lower case for CSS and filtering ("warn"), or "other"
	 */
	public String levelKey() {
		return level.isEmpty() ? "other" : level.toLowerCase(Locale.ROOT);
	}

	/**
	 * @return the full line as a person reads it, used for search and copy
	 */
	public String text() {
		if (level.isEmpty()) {
			return message;
		}
		return date + " " + time + " " + logger + " " + level + " - " + message;
	}
}
