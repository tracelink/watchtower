package com.tracelink.appsec.watchtower.core.mock;

import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class MockRuleEntity extends RuleEntity {

	static final String DEFAULT_AUTHOR = "jdoe";
	static final String DEFAULT_NAME = "Rule Name";
	static final String DEFAULT_MESSAGE = "This is a bad practice.";
	static final String DEFAULT_URL = "https://example.com";
	static final RulePriority DEFAULT_PRIORITY = RulePriority.MEDIUM_HIGH;

	boolean provided = false;

	public MockRuleEntity() {
		setId(1L);
		setAuthor(DEFAULT_AUTHOR);
		setName(DEFAULT_NAME);
		setMessage(DEFAULT_MESSAGE);
		setExternalUrl(DEFAULT_URL);
		setPriority(DEFAULT_PRIORITY);
	}

	public MockRuleEntity(boolean provided) {
		this();
		this.provided = provided;
	}

	@Override
	public RuleDto toDto() {
		if (provided) {
			MockProvidedRuleDto dto = new MockProvidedRuleDto();
			dto.setId(getId());
			dto.setName(getName());
			dto.setMessage(getMessage());
			dto.setExternalUrl(getExternalUrl());
			dto.setPriority(getPriority());
			return dto;
		}
		MockCustomRuleDto dto = new MockCustomRuleDto();
		dto.setId(getId());
		dto.setAuthor(getAuthor());
		dto.setName(getName());
		dto.setMessage(getMessage());
		dto.setExternalUrl(getExternalUrl());
		dto.setPriority(getPriority());
		return dto;
	}
}
