package com.tracelink.appsec.module.eslint.model;

import com.google.gson.annotations.SerializedName;

/**
 * Enum representing valid options for the "type" field of an ESLint rule.
 *
 * @author mcool
 */
public enum EsLintRuleType {
	@SerializedName("problem")
	PROBLEM("problem"),
	@SerializedName("suggestion")
	SUGGESTION("suggestion"),
	@SerializedName("layout")
	LAYOUT("layout");

	private final String value;

	EsLintRuleType(String value) {
		this.value = value;
	}

	String getValue() {
		return value;
	}
}
