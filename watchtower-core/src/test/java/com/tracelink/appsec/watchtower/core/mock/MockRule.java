package com.tracelink.appsec.watchtower.core.mock;

import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class MockRule extends RuleEntity {

	private static final String AUTHOR = "jdoe";
	private static final String NAME = "Rule Name";
	private static final String MESSAGE = "This is a bad practice.";
	private static final String URL = "https://example.com";
	private static final RulePriority PRIORITY = RulePriority.MEDIUM_HIGH;

	public MockRule() {
		setAuthor(AUTHOR);
		setName(NAME);
		setMessage(MESSAGE);
		setExternalUrl(URL);
		setPriority(PRIORITY);
	}

	@Override
	public MockRuleDto toDto() {
		MockRuleDto dto = new MockRuleDto();
		dto.setId(1L);
		dto.setAuthor(getAuthor());
		dto.setName(getName());
		dto.setMessage(getMessage());
		dto.setExternalUrl(getExternalUrl());
		dto.setPriority(getPriority());
		return dto;
	}
}
