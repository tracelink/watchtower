package com.tracelink.appsec.watchtower.core.rule;

import com.fasterxml.jackson.annotation.JsonIgnore;

public abstract class ProvidedRuleDto extends RuleDto {

	@Override
	@JsonIgnore
	public final String getAuthor() {
		return "system";
	}

	@Override
	@JsonIgnore
	public final RuleDesignation getRuleDesignation() {
		return RuleDesignation.PROVIDED;
	}

}
