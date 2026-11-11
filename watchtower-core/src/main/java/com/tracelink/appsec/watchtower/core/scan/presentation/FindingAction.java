package com.tracelink.appsec.watchtower.core.scan.presentation;

/**
 * A link a module offers on one finding of a report, e.g. "Allowlist…".
 *
 * @param label the link text
 * @param url   a Watchtower path, e.g. {@code /betterleaks/allowlist?rule=x}
 * @author Watchtower
 */
public record FindingAction(String label, String url) {

	/**
	 * @throws IllegalArgumentException if the label is blank or the URL is not a same-site path
	 */
	public FindingAction {
		if (label == null || label.isBlank()) {
			throw new IllegalArgumentException("A finding action needs a label");
		}
		if (url == null || !url.startsWith("/") || url.startsWith("//")
				|| url.startsWith("/\\")) {
			throw new IllegalArgumentException("A finding action must link within Watchtower");
		}
	}
}
