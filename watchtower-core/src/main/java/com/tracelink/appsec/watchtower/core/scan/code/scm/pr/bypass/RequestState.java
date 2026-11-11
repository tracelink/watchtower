package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;

/**
 * What a pull request scan report shows about bypass requests (§4.17).
 *
 * @param pending           the pull request's pending request, or null
 * @param viewerIsRequester whether the viewer made that request (they may withdraw, never
 *                          approve or decline it)
 * @author Watchtower
 */
public record RequestState(PullRequestBypassRequestEntity pending, boolean viewerIsRequester) {

	/** No pending request. */
	public static final RequestState NONE = new RequestState(null, false);

	public boolean isPending() {
		return pending != null;
	}
}
