package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;

/**
 * Where a bypass request was made.
 *
 * @author Watchtower
 */
public enum RequestSource {
	/** "Request bypass" on the scan report; the requester is a Watchtower login. */
	WATCHTOWER,
	/**
	 * A {@code /watchtower bypass} pull request comment (§4.18); the requester is an SCM display
	 * name, which can't be matched to a Watchtower login.
	 */
	PR_COMMENT
}
