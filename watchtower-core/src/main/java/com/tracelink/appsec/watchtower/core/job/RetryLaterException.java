package com.tracelink.appsec.watchtower.core.job;

/**
 * Background work could not run now (an SCM rate limit, a dependency briefly down) and should
 * be tried again after a delay rather than marked failed.
 *
 * @author Watchtower
 */
public class RetryLaterException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	private final int delaySeconds;

	public RetryLaterException(String message, int delaySeconds) {
		super(message);
		this.delaySeconds = delaySeconds;
	}

	public int getDelaySeconds() {
		return delaySeconds;
	}
}
