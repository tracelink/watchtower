package com.tracelink.appsec.module.eslint.model;

import com.google.gson.annotations.SerializedName;

/**
 * Enum representing valid options for the "fixable" field of an ESLint rule.
 *
 * @author mcool
 */
public enum EsLintRuleFixable {
	@SerializedName("code")
	CODE("code"),
	@SerializedName("whitespace")
	WHITESPACE("whitespace");

	private final String value;

	EsLintRuleFixable(String value) {
		this.value = value;
	}

	String getValue() {
		return value;
	}
}
