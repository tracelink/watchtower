package com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb;

/** Provider failures contain status metadata only; Bitbucket bodies may echo secrets. */
public class BBWebhookException extends IllegalStateException {
	private final int status;
	private final int retryAfterSeconds;

	public BBWebhookException(int status, int retryAfterSeconds) {
		super("Bitbucket webhook request failed (" + status + ")");
		this.status = status;
		this.retryAfterSeconds = retryAfterSeconds;
	}

	public int getStatus() { return status; }
	public int getRetryAfterSeconds() { return retryAfterSeconds; }
	public String getCode() {
		return switch (status) {
			case 401 -> "CREDENTIALS_REJECTED";
			case 403 -> "MISSING_WEBHOOK_PERMISSION";
			case 404 -> "NOT_FOUND";
			case 409 -> "LIMIT";
			case 429 -> "RATE_LIMITED";
			default -> "ERROR";
		};
	}
}
