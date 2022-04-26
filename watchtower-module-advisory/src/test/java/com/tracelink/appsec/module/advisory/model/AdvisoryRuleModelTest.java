package com.tracelink.appsec.module.advisory.model;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class AdvisoryRuleModelTest {
	public static final String AUTHOR = "Author";
	public static final String URL = "URL";
	public static final String MESSAGE = "message";
	public static final Long ID = 123L;
	public static final String NAME = "name";
	public static final RulePriority PRIORITY = RulePriority.MEDIUM;

	public static AdvisoryRuleEntity makeRule() {
		AdvisoryRuleEntity entity = new AdvisoryRuleEntity();
		entity.setExternalUrl(URL);
		entity.setAuthor(AUTHOR);
		entity.setId(ID);
		entity.setMessage(MESSAGE);
		entity.setName(NAME);
		entity.setPriority(PRIORITY);
		return entity;
	}

	@Test
	public void testRoundtrip() {
		AdvisoryRuleEntity entity = makeRule();

		AdvisoryRuleDto dto = entity.toDto();
		Assertions.assertEquals(AUTHOR, dto.getAuthor());
		Assertions.assertEquals(URL, dto.getExternalUrl());
		Assertions.assertEquals(MESSAGE, dto.getMessage());
		Assertions.assertEquals(NAME, dto.getName());
		Assertions.assertEquals(PRIORITY, dto.getPriority());

		AdvisoryRuleEntity entity2 = dto.toEntity();
		Assertions.assertEquals(AUTHOR, entity2.getAuthor());
		Assertions.assertEquals(URL, entity2.getExternalUrl());
		Assertions.assertEquals(MESSAGE, entity2.getMessage());
		Assertions.assertEquals(0L, entity2.getId());
		Assertions.assertEquals(NAME, entity2.getName());
		Assertions.assertEquals(PRIORITY, entity2.getPriority());

	}
}
