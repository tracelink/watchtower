package com.tracelink.appsec.module.betterleaks.service;

import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.BDDMockito;

import com.tracelink.appsec.module.betterleaks.model.BetterleaksCategory;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksProvidedRuleDto;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksRuleEntity;
import com.tracelink.appsec.module.betterleaks.repository.BetterleaksRuleRepository;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class BetterleaksRuleServiceTest {

	private BetterleaksRuleRepository repository;

	private BetterleaksRuleService service;

	@BeforeEach
	public void setup() {
		repository = BDDMockito.mock(BetterleaksRuleRepository.class);
		service = new BetterleaksRuleService(repository,
				BDDMockito.mock(
						com.tracelink.appsec.module.betterleaks.repository.BetterleaksRuleVersionRepository.class),
				BDDMockito.mock(com.tracelink.appsec.watchtower.core.rule.RuleService.class),
				BDDMockito.mock(BetterleaksRuleTester.class));
	}

	@Test
	public void testEditChangesOnlyThePriority() throws Exception {
		BetterleaksRuleEntity saved = new BetterleaksRuleEntity();
		saved.setProvided(true);
		saved.setName("Betterleaks: github-pat");
		saved.setBetterleaksId("github-pat");
		saved.setMessage("original");
		saved.setCategory(BetterleaksCategory.SCM);
		saved.setPriority(RulePriority.HIGH);
		BDDMockito.when(repository.findById(7L)).thenReturn(Optional.of(saved));
		BetterleaksProvidedRuleDto edit = new BetterleaksProvidedRuleDto();
		edit.setId(7L);
		edit.setName("tampered name");
		edit.setBetterleaksId("tampered-id");
		edit.setMessage("tampered message");
		edit.setPriority(RulePriority.LOW);

		service.editProvidedRule(edit);

		BDDMockito.verify(repository).saveAndFlush(saved);
		Assertions.assertEquals(RulePriority.LOW, saved.getPriority());
		Assertions.assertEquals("Betterleaks: github-pat", saved.getName());
		Assertions.assertEquals("github-pat", saved.getBetterleaksId());
		Assertions.assertEquals("original", saved.getMessage());
	}

	@Test
	public void testEditOfAMissingRuleFails() {
		BDDMockito.when(repository.findById(7L)).thenReturn(Optional.empty());
		BetterleaksProvidedRuleDto edit = new BetterleaksProvidedRuleDto();
		edit.setId(7L);
		edit.setPriority(RulePriority.LOW);

		Assertions.assertThrows(RuleNotFoundException.class, () -> service.editProvidedRule(edit));
	}

	@Test
	public void testEditWithoutAnIdOrPriorityFails() {
		BetterleaksProvidedRuleDto noId = new BetterleaksProvidedRuleDto();
		noId.setPriority(RulePriority.LOW);
		Assertions.assertThrows(RuleNotFoundException.class, () -> service.editProvidedRule(noId));

		BetterleaksProvidedRuleDto noPriority = new BetterleaksProvidedRuleDto();
		noPriority.setId(7L);
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> service.editProvidedRule(noPriority));
		BDDMockito.verify(repository, BDDMockito.never()).saveAndFlush(BDDMockito.any());
	}
}
