package com.tracelink.appsec.module.betterleaks.engine;

import java.util.Locale;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.tracelink.appsec.watchtower.core.verification.LiveVerificationStatus;

/**
 * A finding from a {@code --validation} run: where it is and what the provider said. Like
 * {@link BetterleaksFinding}, the secret has no field to land in. The provider's free-text
 * {@code ValidationReason} is not kept either.
 *
 * @param ruleId           the Betterleaks rule id
 * @param file             the flagged file
 * @param startLine        the 1-based line the finding starts on
 * @param validationStatus Betterleaks' status, e.g. {@code valid}; null when the rule has no
 *                         validation
 * @author Watchtower
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record BetterleaksValidation(@JsonProperty("RuleID") String ruleId,
		@JsonProperty("File") String file, @JsonProperty("StartLine") int startLine,
		@JsonProperty("ValidationStatus") String validationStatus) {

	/**
	 * @return what the status means for Watchtower; anything but a definite answer from the
	 *         provider is {@link LiveVerificationStatus#UNVERIFIABLE}
	 */
	public LiveVerificationStatus toStatus() {
		String status = validationStatus == null ? "" : validationStatus.toLowerCase(Locale.ROOT);
		return switch (status) {
			case "valid" -> LiveVerificationStatus.LIVE;
			case "invalid", "revoked" -> LiveVerificationStatus.INVALID;
			case "error" -> LiveVerificationStatus.ERROR;
			default -> LiveVerificationStatus.UNVERIFIABLE;
		};
	}
}
