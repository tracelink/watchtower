package com.tracelink.appsec.watchtower.core.scan.presentation;

import java.util.regex.Pattern;

/**
 * Rule messages are engine templates ("Consider giving {0} package visibility…"). On rule lists
 * the placeholder reads "this member", the same plain wording reports use for unexpanded
 * historical messages, instead of showing "{0}".
 */
public final class RuleMessageText {
	private static final Pattern PLACEHOLDER = Pattern.compile("'{0,2}\\{[0-9]+\\}'{0,2}");

	private RuleMessageText() {
	}

	public static String readable(String message) {
		if (message == null || !PLACEHOLDER.matcher(message).find()) {
			return message == null ? "" : message;
		}
		String readable = PLACEHOLDER.matcher(message).replaceAll("this member").replaceAll("\\s{2,}", " ").trim();
		return readable.startsWith("this member") ? "T" + readable.substring(1) : readable;
	}
}
