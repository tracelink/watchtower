package com.tracelink.appsec.watchtower.core.rule;

public abstract class ProvidedRuleDto extends RuleDto {

	@Override
	public boolean isProvidedRule() {
		return true;
	}

}
