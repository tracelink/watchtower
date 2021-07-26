package com.tracelink.appsec.watchtower.core.rule;

public abstract class ProvidedRuleDto extends RuleDto {

	@Override
	public String getAuthor() {
		return "system";
	}

	@Override
	public RuleDesignation getRuleDesignation() {
		return RuleDesignation.PROVIDED;
	}

}
