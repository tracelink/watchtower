package com.tracelink.appsec.watchtower.core.process;

import java.time.Duration;

/**
 * Outcome of a process run by {@link ProcessRunner}. Output may contain sensitive data (for
 * example secrets found by a scanner) and must never be logged.
 *
 * @param exitCode        the process exit code, or {@link #TIMED_OUT_EXIT_CODE} if it was killed
 * @param stdout          captured standard output (UTF-8), possibly truncated
 * @param stderr          captured standard error (UTF-8), possibly truncated
 * @param timedOut        whether the process exceeded its timeout and was killed
 * @param stdoutTruncated whether stdout exceeded the output cap
 * @param stderrTruncated whether stderr exceeded the output cap
 * @param elapsed         wall-clock run time
 */
public record ProcessResult(int exitCode, String stdout, String stderr, boolean timedOut,
		boolean stdoutTruncated, boolean stderrTruncated, Duration elapsed) {

	/**
	 * Exit code reported when the process was killed for exceeding its timeout.
	 */
	public static final int TIMED_OUT_EXIT_CODE = -1;

	/**
	 * @return true if the process finished within its timeout with exit code 0
	 */
	public boolean isSuccess() {
		return !timedOut && exitCode == 0;
	}
}
