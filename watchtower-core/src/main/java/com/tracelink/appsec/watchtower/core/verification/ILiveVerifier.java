package com.tracelink.appsec.watchtower.core.verification;

import java.util.Collection;
import java.util.Map;

/**
 * Checks, on request, whether a secret a pull request scan reported still works - to prioritise
 * findings, never as part of a scan. A module that can do this registers a bean; the scan report
 * then offers a "Verify live" action on the findings it {@link #supports(String) supports} to
 * users holding {@link #getPrivilegeName()}.
 * <p>
 * Requests are queued and answered asynchronously; the report shows {@link #getStatuses}.
 *
 * @author Watchtower
 */
public interface ILiveVerifier {

	/**
	 * @return the privilege a user needs to request a verification
	 */
	String getPrivilegeName();

	/**
	 * @param ruleName a violation's rule name
	 * @return true if this verifier handles findings of that rule
	 */
	boolean supports(String ruleName);

	/**
	 * Queues a check of one pull request violation. Repeating a request while one is queued or
	 * running does nothing. Each check contacts a third party, so implementations should bound
	 * how many a user can request.
	 *
	 * @param scanId      the scan whose report the request came from
	 * @param violationId the pull request violation's id; must belong to that scan
	 * @param requestedBy the requesting user's name
	 * @return the violation's status after the request
	 * @throws IllegalArgumentException if the violation is not in that scan, is not supported,
	 *                                  or the user asked for too many checks; the message is safe
	 *                                  to show
	 */
	LiveVerificationStatus request(long scanId, long violationId, String requestedBy);

	/**
	 * @param violationIds pull request violation ids
	 * @return the status of each that has ever been requested; others are absent
	 */
	Map<Long, LiveVerificationStatus> getStatuses(Collection<Long> violationIds);
}
