package com.tracelink.appsec.module.checkov.model;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;


public class CheckovRuleTest {
	public static final String NAME = "DTO";
	public static final String ENTITY = "ENT";
	public static final String IAC = "IAC";
	public static final String TYPE = "Type";
	public static final String EXT_URL = "https://example.com";
	public static final String MESSAGE = "message";
	public static final RulePriority PRIORITY = RulePriority.HIGH;

	public static CheckovProvidedRuleDto createModelRule(boolean core) {
		CheckovProvidedRuleDto dto = new CheckovProvidedRuleDto();
		dto.setId(1L);
		dto.setName(NAME);
		dto.setCheckovRuleName(IAC + NAME);
		dto.setCheckovEntity(ENTITY);
		dto.setCheckovIac(IAC);
		dto.setCheckovType(TYPE);
		dto.setGuidelineUrl(EXT_URL);
		dto.setMessage(MESSAGE);
		dto.setPriority(PRIORITY);
		return dto;
	}

	@Test
	public void testDTO() {
		CheckovProvidedRuleDto dto = CheckovRuleTest.createModelRule(true);
		Assertions.assertEquals(1L, dto.getId().longValue());
		Assertions.assertEquals(NAME, dto.getName());
		Assertions.assertEquals("system", dto.getAuthor());
		Assertions.assertEquals(ENTITY, dto.getCheckovEntity());
		Assertions.assertEquals(IAC, dto.getCheckovIac());
		Assertions.assertEquals(TYPE, dto.getCheckovType());
		Assertions.assertEquals(EXT_URL, dto.getExternalUrl());
		Assertions.assertEquals(MESSAGE, dto.getMessage());
		Assertions.assertEquals(PRIORITY, dto.getPriority());

		CheckovRuleEntity rule = dto.toEntity();
		Assertions.assertEquals(NAME, rule.getName());
		Assertions.assertEquals("system", rule.getAuthor());
		Assertions.assertEquals(ENTITY, rule.getEntity());
		Assertions.assertEquals(IAC, rule.getIac());
		Assertions.assertEquals(TYPE, rule.getType());
		Assertions.assertEquals(EXT_URL, rule.getExternalUrl());
		Assertions.assertEquals(MESSAGE, rule.getMessage());
		Assertions.assertEquals(PRIORITY, rule.getPriority());
	}
}
