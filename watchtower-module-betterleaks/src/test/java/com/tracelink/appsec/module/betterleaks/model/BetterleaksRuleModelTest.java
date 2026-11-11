package com.tracelink.appsec.module.betterleaks.model;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.betterleaks.BetterleaksModule;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class BetterleaksRuleModelTest {

	static BetterleaksProvidedRuleDto providedRule() {
		BetterleaksProvidedRuleDto dto = new BetterleaksProvidedRuleDto();
		dto.setName("Betterleaks: github-pat");
		dto.setBetterleaksId("github-pat");
		dto.setMessage("Uncovered a GitHub Personal Access Token.");
		dto.setExternalUrl("https://github.com/betterleaks/betterleaks");
		dto.setPriority(RulePriority.HIGH);
		dto.setCategory(BetterleaksCategory.SCM);
		dto.setConfidence("high");
		return dto;
	}

	@Test
	public void testDtoToEntityToDtoRoundTrips() {
		BetterleaksProvidedRuleDto original = providedRule();

		BetterleaksRuleEntity entity = original.toEntity();
		BetterleaksProvidedRuleDto copy = (BetterleaksProvidedRuleDto) entity.toDto();

		Assertions.assertTrue(entity.isProvided());
		Assertions.assertEquals("system", entity.getAuthor());
		Assertions.assertEquals(original.getName(), copy.getName());
		Assertions.assertEquals("github-pat", copy.getBetterleaksId());
		Assertions.assertEquals(original.getMessage(), copy.getMessage());
		Assertions.assertEquals(original.getExternalUrl(), copy.getExternalUrl());
		Assertions.assertEquals(RulePriority.HIGH, copy.getPriority());
		Assertions.assertEquals(BetterleaksCategory.SCM, copy.getCategory());
		Assertions.assertEquals("high", copy.getConfidence());
		Assertions.assertEquals(BetterleaksModule.MODULE_NAME, copy.getModule());
	}

	@Test
	public void testANonProvidedEntityBecomesACustomRule() {
		BetterleaksRuleEntity entity = providedRule().toEntity();
		entity.setProvided(false);

		Assertions.assertInstanceOf(BetterleaksCustomRuleDto.class, entity.toDto());
	}
}
