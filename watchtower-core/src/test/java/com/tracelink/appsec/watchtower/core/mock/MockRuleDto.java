package com.tracelink.appsec.watchtower.core.mock;

import com.tracelink.appsec.watchtower.core.rule.CustomRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;

public class MockRuleDto extends CustomRuleDto {
	@Override
	public String getModule() {
		return "Mock";
	}

	@Override
	public RuleEntity toEntity() {
		return new MockRule();
	}
}
