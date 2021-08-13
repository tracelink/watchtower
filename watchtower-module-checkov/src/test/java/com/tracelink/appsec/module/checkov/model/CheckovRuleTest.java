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
		CheckovRuleDefinitionDto def = new CheckovRuleDefinitionDto();
		def.setEntity(ENTITY);
		def.setIac(IAC);
		def.setType(TYPE);
		dto.getDefinitions().add(def);
		dto.setExternalUrl(EXT_URL);
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
		Assertions.assertEquals(EXT_URL, dto.getExternalUrl());
		Assertions.assertEquals(MESSAGE, dto.getMessage());
		Assertions.assertEquals(PRIORITY, dto.getPriority());

		CheckovRuleDefinitionDto def = dto.getDefinitions().get(0);
		Assertions.assertEquals(ENTITY, def.getEntity());
		Assertions.assertEquals(IAC, def.getIac());
		Assertions.assertEquals(TYPE, def.getType());

		CheckovRuleEntity rule = dto.toEntity();
		Assertions.assertEquals(NAME, rule.getName());
		Assertions.assertEquals("system", rule.getAuthor());
		Assertions.assertEquals(EXT_URL, rule.getExternalUrl());
		Assertions.assertEquals(MESSAGE, rule.getMessage());
		Assertions.assertEquals(PRIORITY, rule.getPriority());

		CheckovRuleDefinitionEntity defEnt = rule.getDefinitions().iterator().next();
		Assertions.assertEquals(ENTITY, defEnt.getEntity());
		Assertions.assertEquals(IAC, defEnt.getIac());
		Assertions.assertEquals(TYPE, defEnt.getType());
	}
}
