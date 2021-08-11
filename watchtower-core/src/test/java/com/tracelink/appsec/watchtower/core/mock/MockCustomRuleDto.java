package com.tracelink.appsec.watchtower.core.mock;

import com.tracelink.appsec.watchtower.core.rule.CustomRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;

public class MockCustomRuleDto extends CustomRuleDto {
	@Override
	public String getModule() {
		return "Mock";
	}

	@Override
	public RuleEntity toEntity() {
		MockRuleEntity entity = new MockRuleEntity(false);
		entity.setAuthor(getAuthor());
		entity.setName(getName());
		entity.setMessage(getMessage());
		entity.setExternalUrl(getExternalUrl());
		entity.setPriority(getPriority());
		return entity;
	}
}
