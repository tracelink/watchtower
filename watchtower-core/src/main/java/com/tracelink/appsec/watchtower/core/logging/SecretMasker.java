package com.tracelink.appsec.watchtower.core.logging;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Defence in depth for logs: masks well-known credential formats that should never be logged
 * but might be, e.g. inside an SCM error body or an exception message. Watchtower's own code
 * does not log secrets; this catches the case where something else does. Each token keeps its
 * first four characters so a reader can still tell what kind it was.
 *
 * @author Watchtower
 */
public final class SecretMasker {

	private static final String MASK = "****";

	private static final int KEPT_PREFIX = 4;

	/** Token formats with distinctive prefixes; whole match is masked after the prefix. */
	private static final List<Pattern> TOKENS = List.of(
			Pattern.compile("\\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\\b"),
			Pattern.compile("\\bgh[pousr]_[A-Za-z0-9]{36,255}\\b"),
			Pattern.compile("\\bgithub_pat_[A-Za-z0-9_]{22,255}\\b"),
			Pattern.compile("\\bglpat-[A-Za-z0-9_-]{20,}"),
			Pattern.compile("\\bxox[abposr]-[A-Za-z0-9-]{10,}"),
			Pattern.compile("\\beyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}"));

	private static final Pattern PRIVATE_KEY = Pattern.compile(
			"-----BEGIN ([A-Z ]*)PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)",
			Pattern.DOTALL);

	/** A Chat webhook's query string holds its key and token. */
	private static final Pattern CHAT_WEBHOOK_QUERY =
			Pattern.compile("(chat\\.googleapis\\.com/[^\\s?\"']*\\?)[^\\s\"'<>]+");

	private SecretMasker() {
	}

	/**
	 * @param text any text about to be logged; may be null
	 * @return the text with known credential formats masked
	 */
	public static String mask(String text) {
		if (text == null || text.isEmpty()) {
			return text;
		}
		String masked = PRIVATE_KEY.matcher(text)
				.replaceAll("-----BEGIN $1PRIVATE KEY-----" + MASK);
		masked = CHAT_WEBHOOK_QUERY.matcher(masked).replaceAll("$1" + MASK);
		for (Pattern token : TOKENS) {
			Matcher matcher = token.matcher(masked);
			if (matcher.find()) {
				masked = matcher.replaceAll(match -> Matcher.quoteReplacement(
						match.group().substring(0, KEPT_PREFIX) + MASK));
			}
		}
		return masked;
	}
}
