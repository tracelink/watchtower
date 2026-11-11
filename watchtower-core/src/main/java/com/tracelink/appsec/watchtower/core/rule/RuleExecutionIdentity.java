package com.tracelink.appsec.watchtower.core.rule;

import java.util.Locale;
import java.util.Objects;

/**
 * Immutable identity captured from the selected scan definition, never reconstructed from a later
 * name lookup. Numeric ids are installation-local; origin keys are explicit upstream identifiers.
 * A null revision/id denotes unavailable evidence, including unmanaged engine findings. This is
 * independent of name-based RuleDto equality and can distinguish revisions of one logical rule.
 */
public record RuleExecutionIdentity(Long ruleId, String module, String revision,
		String externalRuleKey, String originKey) {

	public RuleExecutionIdentity {
		Objects.requireNonNull(module, "Rule module is required");
		if (module.isBlank() || (ruleId != null && ruleId <= 0)
				|| (revision != null && !revision.matches("[0-9a-f]{64}"))) {
			throw new IllegalArgumentException("Invalid rule execution identity");
		}
		module = module.toLowerCase(Locale.ROOT);
	}

	public static RuleExecutionIdentity unmanaged(String module, String externalRuleKey) {
		return new RuleExecutionIdentity(null, module, null, externalRuleKey, null);
	}
}
