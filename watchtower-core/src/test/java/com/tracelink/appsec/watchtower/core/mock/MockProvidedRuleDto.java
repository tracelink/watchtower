package com.tracelink.appsec.watchtower.core.mock;

import com.tracelink.appsec.watchtower.core.rule.ProvidedRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;

public class MockProvidedRuleDto extends ProvidedRuleDto {
	private String message;
	private String externalUrl;

	@Override
	public String getModule() {
		return "Mock";
	}

	@Override
	public RuleEntity toEntity() {
		MockRuleEntity entity = new MockRuleEntity(isProvided());
		entity.setAuthor(getAuthor());
		entity.setName(getName());
		entity.setMessage(getMessage());
		entity.setExternalUrl(getExternalUrl());
		entity.setPriority(getPriority());
		return entity;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public void setExternalUrl(String externalUrl) {
		this.externalUrl = externalUrl;
	}

	@Override
	public String getMessage() {
		return message;
	}

	@Override
	public String getExternalUrl() {
		return externalUrl;
	}
}
