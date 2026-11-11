package com.tracelink.appsec.watchtower.core.scan.presentation;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * An advisory's CVSS score and vector in plain words for the image report (UAT walkthrough,
 * 2026-10-16): "CVSS 5.0 · Medium" coloured by its band, "No CVSS" instead of "N/A", and the
 * vector as "Network · No auth · Availability" with the raw code kept for hover and copy.
 */
public record CvssText(Double score, String rawScore, String vector) {

	private static final double CRITICAL = 9.0;
	private static final double HIGH = 7.0;
	private static final double MEDIUM = 4.0;
	private static final double NONE = 0.0;

	/**
	 * @param score  the advisory's score as stored (may be blank or "N/A")
	 * @param vector the advisory's CVSS vector, or null
	 * @return the presentation of both
	 */
	public static CvssText of(String score, String vector) {
		Double parsed = null;
		if (score != null && !score.isBlank()) {
			try {
				parsed = Double.valueOf(score.trim());
			} catch (NumberFormatException notANumber) {
				parsed = null;
			}
		}
		return new CvssText(parsed, score, vector == null || vector.isBlank() ? null : vector.trim());
	}

	public boolean scored() {
		return score != null;
	}

	/** "CVSS 5.0" for the findings list, or "No CVSS". */
	public String shortLabel() {
		return scored() ? "CVSS " + formatted() : "No CVSS";
	}

	/** "CVSS 5.0 · Medium" for the finding detail, or "No CVSS". */
	public String label() {
		return scored() ? shortLabel() + " · " + band() : "No CVSS";
	}

	public String scoreTip() {
		return scored() ? "CVSS base score " + formatted() + " out of 10" : "The advisory has no CVSS score";
	}

	/** The severity key the chip borrows its colour from (the same keys as the severity pills). */
	public String severityKey() {
		if (!scored()) {
			return "UNKNOWN";
		}
		if (score >= CRITICAL) {
			return "CRITICAL";
		}
		if (score >= HIGH) {
			return "1";
		}
		if (score >= MEDIUM) {
			return "3";
		}
		return score > NONE ? "5" : "6";
	}

	/** The vector in plain words, the raw code when it can't be read, or null without a vector. */
	public String vectorText() {
		if (vector == null) {
			return null;
		}
		Map<String, String> metrics = metrics();
		String access = accessWords(metrics.get("AV"));
		if (access == null) {
			return vector;
		}
		List<String> parts = new ArrayList<>(List.of(access, authWords(metrics)));
		String impact = impactWords(metrics);
		if (!impact.isEmpty()) {
			parts.add(impact);
		}
		return String.join(" · ", parts);
	}

	/** Hover text: the raw vector, what it means, and that a click copies it. */
	public String vectorTip() {
		if (vector == null) {
			return null;
		}
		Map<String, String> metrics = metrics();
		String reach = switch (metrics.getOrDefault("AV", "")) {
			case "N" -> "reachable over the network";
			case "A" -> "reachable from the local network";
			case "L" -> "needs local access";
			case "P" -> "needs physical access";
			default -> null;
		};
		if (reach == null) {
			return "Vector " + vector + ". Click to copy.";
		}
		String complexity = "H".equals(metrics.get("AC")) ? "high complexity" : "low complexity";
		String login = authWords(metrics).equals("No auth") ? "no login needed" : "a login is needed";
		String impact = impactWords(metrics);
		String affects = impact.isEmpty() ? "no direct impact recorded"
				: "affects " + impact.toLowerCase(Locale.ROOT).replace(", ", " and ");
		return "Vector " + vector + ": " + reach + ", " + complexity + ", " + login + ", " + affects
				+ ". Click to copy.";
	}

	private String formatted() {
		return String.format(Locale.ROOT, "%.1f", score);
	}

	private String band() {
		if (score >= CRITICAL) {
			return "Critical";
		}
		if (score >= HIGH) {
			return "High";
		}
		if (score >= MEDIUM) {
			return "Medium";
		}
		return score > NONE ? "Low" : "None";
	}

	private Map<String, String> metrics() {
		Map<String, String> metrics = new HashMap<>();
		for (String part : vector.split("/")) {
			int colon = part.indexOf(':');
			if (colon > 0 && colon < part.length() - 1) {
				metrics.put(part.substring(0, colon), part.substring(colon + 1));
			}
		}
		return metrics;
	}

	private static String accessWords(String code) {
		if (code == null) {
			return null;
		}
		return switch (code) {
			case "N" -> "Network";
			case "A" -> "Adjacent network";
			case "L" -> "Local";
			case "P" -> "Physical";
			default -> null;
		};
	}

	/** CVSS v2 "Au:N" and v3 "PR:N" both mean no login is needed. */
	private static String authWords(Map<String, String> metrics) {
		String code = metrics.containsKey("PR") ? metrics.get("PR") : metrics.get("Au");
		return "N".equals(code) ? "No auth" : "Login needed";
	}

	private static String impactWords(Map<String, String> metrics) {
		List<String> affected = new ArrayList<>();
		if (impacted(metrics.get("C"))) {
			affected.add("Confidentiality");
		}
		if (impacted(metrics.get("I"))) {
			affected.add("Integrity");
		}
		if (impacted(metrics.get("A"))) {
			affected.add("Availability");
		}
		return String.join(", ", affected);
	}

	private static boolean impacted(String code) {
		return code != null && !"N".equals(code);
	}
}
