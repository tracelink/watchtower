package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.queue;

/**
 * What to do with a queue message after its work ran: remove it, or let it come back later.
 *
 * @param retry        true to redeliver the message after {@code delaySeconds}
 * @param delaySeconds how long to wait before redelivery
 * @author Watchtower
 */
public record WorkOutcome(boolean retry, int delaySeconds) {

	private static final WorkOutcome DONE = new WorkOutcome(false, 0);

	/** The work finished, failed for good, or was a duplicate: remove the message. */
	public static WorkOutcome done() {
		return DONE;
	}

	/** The work could not run now (rate limit, busy): deliver it again later. */
	public static WorkOutcome retryLater(int delaySeconds) {
		return new WorkOutcome(true, Math.max(1, delaySeconds));
	}
}
