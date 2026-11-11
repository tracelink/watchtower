package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;

/**
 * What a pull request scan report shows about bypassing.
 *
 * @param blocked whether the scan blocked its pull request
 * @param refusal why a blocked scan cannot be bypassed now, or null if it can
 * @param active  the pull request's active bypass, or null
 * @author Watchtower
 */
public record BypassState(boolean blocked, String refusal, ActiveBypass active) {

	/** A scan that is unknown, or offers nothing to bypass or revoke. */
	public static final BypassState NONE = new BypassState(false, null, null);

	/**
	 * @return true if "Bypass blocking" can be used on this scan
	 */
	public boolean canBypass() {
		return blocked && refusal == null;
	}

	/**
	 * @return true if the pull request has an active bypass to show and revoke
	 */
	public boolean isActive() {
		return active != null;
	}
}
