package com.tracelink.appsec.watchtower.core.job;

import java.util.function.Consumer;

/**
 * Runs one type of background job.
 *
 * @author Watchtower
 */
public interface AsyncJobHandler {

	AsyncJobType type();

	/**
	 * @param job      the claimed job
	 * @param progress reports a short progress note shown on the queue view
	 * @return a key naming the job's result (for example an export object), or null
	 * @throws RetryLaterException if the job cannot run now and should be retried
	 * @throws Exception           if the job failed for good; the message is shown to admins,
	 *                             so it must not contain secrets or source
	 */
	String handle(AsyncJobEntity job, Consumer<String> progress) throws Exception;
}
