package com.tracelink.appsec.watchtower.core.exception;

/**
 * Thrown when Bitbucket's rate limiter cannot be satisfied by the usual bounded
 * blocking retry (IMPROVEMENT_PLAN.md item 4.7). Unlike
 * {@linkplain ScanRejectedException} and its relatives, this is not a permanent
 * rejection - the caller is expected to retry later, ideally via
 * {@code SqsScanQueueService.requeue(String, int)} with {@link #getRetryAfterSeconds()}
 * as the delay, rather than failing the scan outright.
 * <p>
 * A {@link RuntimeException}, not a checked exception: it needs to propagate through
 * {@code IScmApi} methods (e.g. {@code getChangedFilesForPullRequest},
 * {@code downloadFileAtCommit}) that either declare no checked exceptions or declare
 * only {@link java.io.IOException}, without widening either signature.
 *
 * @author Watchtower
 */
public class RateLimitedException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	private final int retryAfterSeconds;

	public RateLimitedException(int retryAfterSeconds) {
		super("Rate limited by Bitbucket; retry after " + retryAfterSeconds + "s");
		this.retryAfterSeconds = retryAfterSeconds;
	}

	/**
	 * @return the delay, in seconds, Bitbucket's {@code Retry-After} header indicated
	 *         before this request should be attempted again
	 */
	public int getRetryAfterSeconds() {
		return retryAfterSeconds;
	}
}
