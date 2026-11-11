package com.tracelink.appsec.watchtower.core.rule.report;

import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Plain words for the saved review report page (UAT walkthrough, 2026-10-16): the reason codes
 * stored with each attention row (CONFIRMED_NOISE, NO_OWNER, …) become labelled buttons and chips,
 * and "2026-W42" becomes "Week 42". The server still filters on the stored codes.
 */
public final class RuleReportPresentation {

	/** One attention reason: stored code, words, icon and its meaning on hover. */
	public record Reason(String code, String label, String icon, String tip) {
	}

	/** The reason filter, in the order the board shows it ("all" first). */
	public static final List<Reason> REASONS = List.of(
			new Reason("NO_OWNER", "No owner", "person_off", "No owner is set. A setup gap, not a sign the rule is wrong."),
			new Reason("NO_CWE", "No CWE", "label_off", "No CWE category is mapped. A setup gap, not missing detection."),
			new Reason("REVIEW_OVERDUE", "Review overdue", "event_busy", "The rule's review-by date had passed."),
			new Reason("CONFIRMED_NOISE", "Confirmed noise", "volume_off",
					"Most reviewed findings were false positives (90 days)."),
			new Reason("NO_RECENT_MATCHES", "No recent matches", "search_off",
					"The engine ran but the rule matched nothing in 90 days. That can mean the risk is absent; "
							+ "it is not a reason to retire the rule."));

	private static final Pattern WEEK = Pattern.compile("\\d{4}-W(\\d{1,2})");

	private static final List<String> WEEKDAYS = List.of("Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
			"Saturday", "Sunday");

	private RuleReportPresentation() {
	}

	/** The reason for a stored code; an unknown code keeps its code as words. */
	public static Reason reason(String code) {
		return REASONS.stream().filter(r -> r.code().equals(code)).findFirst()
				.orElse(new Reason(code, code, "info", code));
	}

	/** "Week 42" for a scheduled period key; "Manual" for a report someone ran. */
	public static String periodLabel(String period) {
		if (period == null) {
			return "Manual";
		}
		Matcher week = WEEK.matcher(period);
		return week.matches() ? "Week " + Integer.parseInt(week.group(1)) : period;
	}

	/** "Weekly · Monday (UTC)" or "Schedule off", from the settings map the service returns. */
	public static String scheduleLabel(Map<String, Object> settings) {
		if (settings == null || !Boolean.TRUE.equals(settings.get("enabled"))) {
			return "Schedule off";
		}
		return "Weekly · " + weekday(settings.get("weekday")) + " (UTC)";
	}

	private static String weekday(Object value) {
		int day = value instanceof Number number ? number.intValue() : 1;
		return day >= 1 && day <= WEEKDAYS.size() ? WEEKDAYS.get(day - 1) : "Monday";
	}
}
