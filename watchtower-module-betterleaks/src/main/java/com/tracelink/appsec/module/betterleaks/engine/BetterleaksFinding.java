package com.tracelink.appsec.module.betterleaks.engine;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The only parts of a Betterleaks finding Watchtower keeps: which rule fired, where. The report's
 * {@code Match} and {@code Secret} fields are deliberately not mapped, so the secret has nowhere
 * to live even if a binary ever ignored {@code --redact}.
 *
 * @param ruleId    the Betterleaks rule id
 * @param file      the flagged file, as Betterleaks reports it
 * @param startLine the 1-based line the finding starts on
 * @author Watchtower
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record BetterleaksFinding(@JsonProperty("RuleID") String ruleId,
		@JsonProperty("File") String file, @JsonProperty("StartLine") int startLine) {
}
