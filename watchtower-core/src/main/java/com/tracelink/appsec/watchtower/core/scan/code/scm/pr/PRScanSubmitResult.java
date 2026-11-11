package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

/**
 * The outcome of submitting a Pull Request for scanning.
 * <p>
 * Submission used to return void, so a caller could not tell a queued scan from one
 * that was silently dropped. A webhook received HTTP 200 either way, Bitbucket recorded
 * the delivery as successful, and nothing had been scanned.
 *
 * @author csmith
 */
public enum PRScanSubmitResult {
	/** The scan was queued for execution. */
	QUEUED("Scan queued", true),

	/** An identical scan for the same commit was already queued or running. */
	DEDUPLICATED("An identical scan is already in flight", true),

	/** The Pull Request is already merged or declined, so it was resolved unscanned. */
	ALREADY_RESOLVED("Pull Request is already closed; resolved without scanning", true),

	/**
	 * A person paused scanning of the repository. Not a failure: the webhook succeeded, and the
	 * pull request gets no comment.
	 */
	PAUSED("Scanning is paused for this repository", true),

	/** The repository has no ruleset configured, so there is nothing to scan against. */
	NO_RULESET("Repository is not configured with a ruleset", false),

	/** No scanners are installed, so no scan can produce results. */
	NO_SCANNERS("No scanners are configured", false);

	private final String description;
	private final boolean accepted;

	PRScanSubmitResult(String description, boolean accepted) {
		this.description = description;
		this.accepted = accepted;
	}

	public String getDescription() {
		return this.description;
	}

	/**
	 * Whether the submission was handled as intended. False means the request was
	 * understood but could not be acted on, which callers should surface as a failure
	 * rather than a success.
	 *
	 * @return true if the submission was handled
	 */
	public boolean isAccepted() {
		return this.accepted;
	}
}
