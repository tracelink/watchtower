package com.tracelink.appsec.watchtower.core.scan.code.scm.api;

/**
 * A file read from a source control server: its content, or the reason it could not be read,
 * in words for the person looking at a report that has no code to show.
 *
 * @param content the file's text, or null when it could not be read
 * @param reason  why there is no content; null when there is
 */
public record FileFetch(String content, String reason) {

	/** The fallback wording when an integration cannot tell why. */
	public static final String UNKNOWN_REASON = "The source control server did not return the file.";

	public static FileFetch found(String content) {
		return new FileFetch(content, null);
	}

	public static FileFetch unavailable(String reason) {
		return new FileFetch(null, reason == null || reason.isBlank() ? UNKNOWN_REASON : reason);
	}

	public boolean isFound() {
		return content != null;
	}
}
