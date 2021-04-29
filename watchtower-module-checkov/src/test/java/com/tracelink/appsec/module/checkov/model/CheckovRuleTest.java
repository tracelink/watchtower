package com.tracelink.appsec.module.checkov.model;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;


public class CheckovRuleTest {
	public static final String NAME = "DTO";
	public static final String AUTHOR = "User";
	public static final String ENTITY = "ENT";
	public static final String IAC = "IAC";
	public static final String TYPE = "Type";
	public static final String EXT_URL = "https://example.com";
	public static final String MESSAGE = "message";
	public static final RulePriority PRIORITY = RulePriority.HIGH;

	public static CheckovRuleDto createModelRule(boolean core) {
		CheckovRuleDto dto = new CheckovRuleDto();
		dto.setId(1L);
		dto.setName(NAME);
		dto.setAuthor(AUTHOR);
		dto.setCheckovEntity(ENTITY);
		dto.setCheckovIac(IAC);
		dto.setCheckovType(TYPE);
		dto.setCoreRule(core);
		dto.setExternalUrl(EXT_URL);
		dto.setMessage(MESSAGE);
		dto.setPriority(PRIORITY);
		return dto;
	}

	@Test
	public void testDTO() {
		String code = "somecode";
		CheckovRuleDto dto = CheckovRuleTest.createModelRule(true);
		dto.setCode(code);
		Assertions.assertEquals(1L, dto.getId().longValue());
		Assertions.assertEquals(NAME, dto.getName());
		Assertions.assertEquals(AUTHOR, dto.getAuthor());
		Assertions.assertEquals(ENTITY, dto.getCheckovEntity());
		Assertions.assertEquals(IAC, dto.getCheckovIac());
		Assertions.assertEquals(TYPE, dto.getCheckovType());
		Assertions.assertEquals(true, dto.isCoreRule());
		Assertions.assertEquals(EXT_URL, dto.getExternalUrl());
		Assertions.assertEquals(MESSAGE, dto.getMessage());
		Assertions.assertEquals(PRIORITY, dto.getPriority());
		Assertions.assertEquals(code, dto.getCode());

		CheckovRuleEntity rule = dto.toEntity();
		Assertions.assertEquals(NAME, rule.getName());
		Assertions.assertEquals(AUTHOR, rule.getAuthor());
		Assertions.assertEquals(ENTITY, rule.getEntity());
		Assertions.assertEquals(IAC, rule.getIac());
		Assertions.assertEquals(TYPE, rule.getType());
		Assertions.assertEquals(true, rule.isCoreRule());
		Assertions.assertEquals(EXT_URL, rule.getExternalUrl());
		Assertions.assertEquals(MESSAGE, rule.getMessage());
		Assertions.assertEquals(PRIORITY, rule.getPriority());
		Assertions.assertEquals(code, rule.getCode());

		CheckovRuleDto dto2 = rule.toDto();
		Assertions.assertEquals(NAME, dto2.getName());
		Assertions.assertEquals(AUTHOR, dto2.getAuthor());
		Assertions.assertEquals(ENTITY, dto2.getCheckovEntity());
		Assertions.assertEquals(IAC, dto2.getCheckovIac());
		Assertions.assertEquals(TYPE, dto2.getCheckovType());
		Assertions.assertEquals(true, dto2.isCoreRule());
		Assertions.assertEquals(EXT_URL, dto2.getExternalUrl());
		Assertions.assertEquals(MESSAGE, dto2.getMessage());
		Assertions.assertEquals(PRIORITY, dto2.getPriority());
		Assertions.assertEquals(code, dto2.getCode());


	}
}
