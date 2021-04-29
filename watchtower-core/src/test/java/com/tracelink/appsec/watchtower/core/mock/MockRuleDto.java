package com.tracelink.appsec.watchtower.core.mock;

import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;

public class MockRuleDto extends RuleDto {
	@Override
	public String getModule() {
		return "Mock";
	}

	@Override
	public RuleEntity toEntity() {
		return new MockRule();
	}
}
