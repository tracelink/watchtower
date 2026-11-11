package com.tracelink.appsec.watchtower.core.rule;

import java.time.LocalDate;

import org.springframework.format.annotation.DateTimeFormat;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** Only these fields can be changed through the stewardship form. */
public record RuleStewardshipUpdate(
		@NotNull RuleState state,
		@Size(max = 255) String owner,
		@DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate reviewBy,
		@Pattern(regexp = "(?:CWE-[1-9][0-9]{0,8})?") String cwe,
		@Pattern(regexp = "(?:CWE-[1-9][0-9]{0,8}(?:,CWE-[1-9][0-9]{0,8}){0,9})?") String secondaryCwes,
		Boolean notSecurity,
		@Size(max = 128) String category) {
	public RuleStewardshipUpdate {
		owner = clean(owner);
		cwe = clean(cwe);
		secondaryCwes = cleanList(secondaryCwes);
		// A form that does not send the switch means it is off.
		notSecurity = Boolean.TRUE.equals(notSecurity);
		category = clean(category);
	}

	/** The form as it was before secondary CWEs: a security rule with a primary CWE only. */
	public RuleStewardshipUpdate(RuleState state, String owner, LocalDate reviewBy, String cwe, String category) {
		this(state, owner, reviewBy, cwe, null, false, category);
	}

	/** {@code " cwe-1 , CWE-2 "} becomes {@code "CWE-1,CWE-2"}; anything that is not a list of CWEs is left to fail validation. */
	private static String cleanList(String value) {
		if (value == null || value.isBlank()) {
			return null;
		}
		return java.util.Arrays.stream(value.split(",", -1)).map(String::strip).filter(part -> !part.isEmpty())
				.map(part -> part.toUpperCase(java.util.Locale.ROOT)).collect(java.util.stream.Collectors.joining(","));
	}

	private static String clean(String value) {
		return value == null || value.isBlank() ? null : value.strip();
	}
}
