package com.tracelink.appsec.watchtower.core.scan.presentation;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Plain-word titles for provider (AWS Security Agent) findings: "Privilege escalation" rather
 * than "Sensitive AWS finding: PRIVILEGE_ESCALATION", and "Tenant isolation" rather than
 * "[Requirement: ASA Base Pack/tenant-isolation]".
 */
public final class ProviderFindingTitles {
	private static final String FALLBACK = "AWS security finding";
	private static final Pattern REQUIREMENT = Pattern.compile("^\\s*\\[Requirement:\\s*([^\\]]*)\\]?\\s*(.*)$",
			Pattern.DOTALL);
	private static final Pattern CODE_PREFIX = Pattern.compile(
			"^(?:Sensitive AWS finding|AWS security finding):\\s*(.*)$", Pattern.DOTALL);
	private static final int MAX_LENGTH = 120;

	private ProviderFindingTitles() {
	}

	/**
	 * @param name     the provider's (or the saved) title; may be null
	 * @param riskType the provider's risk type code, such as PRIVILEGE_ESCALATION; may be null
	 * @return a short title in plain words, never a code
	 */
	public static String plain(String name, String riskType) {
		String text = name == null ? "" : name.strip();
		Matcher code = CODE_PREFIX.matcher(text);
		if (code.matches()) {
			text = code.group(1).strip();
		}
		Matcher requirement = REQUIREMENT.matcher(text);
		if (requirement.matches()) {
			String slug = requirement.group(1);
			String rest = requirement.group(2).strip();
			String fromSlug = humanize(slug.substring(slug.lastIndexOf('/') + 1));
			text = fromSlug.isEmpty() ? rest : fromSlug;
		} else if (isCode(text)) {
			text = humanize(text);
		}
		if (text.isEmpty() && riskType != null) {
			text = humanize(riskType);
		}
		if (text.isEmpty() || "Unknown".equalsIgnoreCase(text)) {
			return FALLBACK;
		}
		return text.length() > MAX_LENGTH ? text.substring(0, MAX_LENGTH - 1).strip() + "…" : text;
	}

	/** A code such as PRIVILEGE_ESCALATION or tenant-isolation: no spaces, only letters, digits and separators. */
	private static boolean isCode(String text) {
		return !text.isEmpty() && text.matches("[A-Za-z0-9_.:-]+") && (text.contains("_") || text.contains("-")
				|| text.equals(text.toUpperCase(Locale.ROOT)));
	}

	/** "PRIVILEGE_ESCALATION" and "tenant-isolation" read "Privilege escalation" and "Tenant isolation". */
	static String humanize(String code) {
		String words = code == null ? "" : code.replaceAll("[_\\-.:]+", " ").strip().toLowerCase(Locale.ROOT);
		if (words.isEmpty()) {
			return "";
		}
		words = words.replaceAll("\\bsql\\b", "SQL").replaceAll("\\bxss\\b", "XSS").replaceAll("\\baws\\b", "AWS")
				.replaceAll("\\biam\\b", "IAM").replaceAll("\\bapi\\b", "API").replaceAll("\\b500\\b", "500");
		return Character.toUpperCase(words.charAt(0)) + words.substring(1);
	}
}
