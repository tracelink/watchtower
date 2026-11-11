package com.tracelink.appsec.module.betterleaks.engine;

/**
 * A Betterleaks scan could not produce a trustworthy result. The message is shown in scan errors,
 * so it never carries scanner output.
 *
 * @author Watchtower
 */
public class BetterleaksScanException extends Exception {
	private static final long serialVersionUID = 1L;

	/** Why the scan failed, for metrics and alerting. */
	public enum Reason {
		TIMEOUT, EXIT_CODE, OUTPUT_LIMIT, UNREADABLE_OUTPUT, START_FAILURE, PREPARATION,
		INVALID_RULE, OTHER
	}

	private final Reason reason;

	public BetterleaksScanException(String message) {
		this(Reason.OTHER, message);
	}

	public BetterleaksScanException(Reason reason, String message) {
		super(message);
		this.reason = reason;
	}

	public Reason getReason() {
		return reason;
	}
}
