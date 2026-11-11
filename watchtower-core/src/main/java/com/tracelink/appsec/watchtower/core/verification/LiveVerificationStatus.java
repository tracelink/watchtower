package com.tracelink.appsec.watchtower.core.verification;

/**
 * The outcome of checking whether a reported secret still works. Only {@link #LIVE} is a
 * definite answer that it does; nothing here means "safe" - an unverifiable or rejected secret
 * must still be removed.
 *
 * @author Watchtower
 */
public enum LiveVerificationStatus {
	PENDING("Verifying", "The provider check is queued or running."),
	LIVE("Live - rotate now", "The provider accepted the secret. Rotate it; removing it from the"
			+ " code is not enough."),
	INVALID("Rejected by provider", "The provider rejected the secret (invalid or revoked). It"
			+ " must still be removed."),
	UNVERIFIABLE("Not verifiable", "No provider check exists for this kind of secret, or it could"
			+ " not be found as scanned. This is not proof that it is safe."),
	ERROR("Verification failed", "The provider check did not complete. Try again later.");

	private final String label;

	private final String description;

	LiveVerificationStatus(String label, String description) {
		this.label = label;
		this.description = description;
	}

	public String getLabel() {
		return label;
	}

	public String getDescription() {
		return description;
	}
}
