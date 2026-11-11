package com.tracelink.appsec.module.betterleaks.service;

import java.util.List;
import java.util.Optional;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;

import com.tracelink.appsec.module.betterleaks.engine.BetterleaksRuleTestResult;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDtoTest;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksRuleEntity;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksRuleVersionEntity;
import com.tracelink.appsec.module.betterleaks.repository.BetterleaksRuleRepository;
import com.tracelink.appsec.module.betterleaks.repository.BetterleaksRuleVersionRepository;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleService;

public class BetterleaksCustomRuleServiceTest {

	private static final BetterleaksRuleTestResult PASSES =
			new BetterleaksRuleTestResult(true, false, null);

	private BetterleaksRuleRepository ruleRepository;

	private BetterleaksRuleVersionRepository versionRepository;

	private RuleService coreRuleService;

	private BetterleaksRuleTester tester;

	private BetterleaksRuleService service;

	@BeforeEach
	public void setup() {
		ruleRepository = BDDMockito.mock(BetterleaksRuleRepository.class);
		versionRepository = BDDMockito.mock(BetterleaksRuleVersionRepository.class);
		coreRuleService = BDDMockito.mock(RuleService.class);
		tester = BDDMockito.mock(BetterleaksRuleTester.class);
		BDDMockito.when(ruleRepository.saveAndFlush(BDDMockito.any()))
				.thenAnswer(invocation -> invocation.getArgument(0));
		service = new BetterleaksRuleService(ruleRepository, versionRepository, coreRuleService,
				tester);
	}

	private BetterleaksRuleVersionEntity savedVersion() {
		ArgumentCaptor<BetterleaksRuleVersionEntity> captor =
				ArgumentCaptor.forClass(BetterleaksRuleVersionEntity.class);
		BDDMockito.verify(versionRepository).save(captor.capture());
		return captor.getValue();
	}

	@Test
	public void testSavesATestedRuleAsVersionOneWithHistory() throws Exception {
		BetterleaksCustomRuleDto rule = BetterleaksCustomRuleDtoTest.validRule();
		BDDMockito.when(tester.test(rule)).thenReturn(PASSES);

		service.saveNewCustomRule(rule, "alice");

		ArgumentCaptor<BetterleaksRuleEntity> saved =
				ArgumentCaptor.forClass(BetterleaksRuleEntity.class);
		BDDMockito.verify(ruleRepository).saveAndFlush(saved.capture());
		Assertions.assertFalse(saved.getValue().isProvided());
		Assertions.assertEquals("alice", saved.getValue().getAuthor());
		Assertions.assertEquals(1, saved.getValue().getRuleVersion());
		BetterleaksRuleVersionEntity version = savedVersion();
		Assertions.assertEquals(1, version.getRuleVersion());
		Assertions.assertEquals("alice", version.getAuthor());
		MatcherAssert.assertThat(version.getDefinition(),
				Matchers.containsString("tlk_int_[A-Za-z0-9]{16}"));
	}

	@Test
	public void testRefusesARuleThatFailsItsSampleTest() {
		BetterleaksCustomRuleDto rule = BetterleaksCustomRuleDtoTest.validRule();
		BDDMockito.when(tester.test(rule))
				.thenReturn(new BetterleaksRuleTestResult(true, true, null));

		IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
				() -> service.saveNewCustomRule(rule, "alice"));

		MatcherAssert.assertThat(e.getMessage(), Matchers.containsString("negative sample"));
		BDDMockito.verify(ruleRepository, BDDMockito.never()).saveAndFlush(BDDMockito.any());
	}

	@Test
	public void testRefusesADuplicateName() {
		BetterleaksCustomRuleDto rule = BetterleaksCustomRuleDtoTest.validRule();
		BDDMockito.when(coreRuleService.getRule(rule.getName()))
				.thenReturn(BDDMockito.mock(RuleEntity.class));

		Assertions.assertThrows(IllegalArgumentException.class,
				() -> service.saveNewCustomRule(rule, "alice"));
		BDDMockito.verifyNoInteractions(tester);
	}

	@Test
	public void testEditBumpsTheVersionAndKeepsTheIdentity() throws Exception {
		BetterleaksRuleEntity existing = BetterleaksCustomRuleDtoTest.validRule().toEntity();
		existing.setAuthor("alice");
		BDDMockito.when(ruleRepository.findById(9L)).thenReturn(Optional.of(existing));
		BDDMockito.when(tester.test(BDDMockito.any())).thenReturn(PASSES);
		BetterleaksCustomRuleDto edit = BetterleaksCustomRuleDtoTest.validRule();
		edit.setId(9L);
		edit.setBetterleaksId("custom-renamed");
		edit.setName("Betterleaks: custom-renamed");
		edit.setRegex("tlk_int_[A-Za-z0-9]{16,20}");
		edit.setPriority(RulePriority.LOW);

		service.editCustomRule(edit, "bob");

		Assertions.assertEquals("custom-example-internal-token", existing.getBetterleaksId());
		Assertions.assertEquals("Betterleaks: custom-example-internal-token", existing.getName());
		Assertions.assertEquals("tlk_int_[A-Za-z0-9]{16,20}", existing.getRegex());
		Assertions.assertEquals(RulePriority.LOW, existing.getPriority());
		Assertions.assertEquals(2, existing.getRuleVersion());
		Assertions.assertEquals("alice", existing.getAuthor());
		Assertions.assertEquals("bob", savedVersion().getAuthor());
		Assertions.assertEquals(2, savedVersion().getRuleVersion());
	}

	@Test
	public void testEditOfAProvidedOrMissingRuleFails() {
		BetterleaksRuleEntity provided = new BetterleaksRuleEntity();
		provided.setProvided(true);
		BDDMockito.when(ruleRepository.findById(1L)).thenReturn(Optional.of(provided));
		BDDMockito.when(ruleRepository.findById(2L)).thenReturn(Optional.empty());
		BetterleaksCustomRuleDto edit = BetterleaksCustomRuleDtoTest.validRule();

		edit.setId(1L);
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> service.editCustomRule(edit, "bob"));
		edit.setId(2L);
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> service.editCustomRule(edit, "bob"));
	}

	@Test
	public void testVersionsAreNewestFirst() {
		BetterleaksRuleVersionEntity v1 = new BetterleaksRuleVersionEntity();
		v1.setRuleVersion(1);
		BetterleaksRuleVersionEntity v2 = new BetterleaksRuleVersionEntity();
		v2.setRuleVersion(2);
		BDDMockito.when(versionRepository.findByRuleId(9L)).thenReturn(List.of(v1, v2));

		Assertions.assertEquals(List.of(v2, v1), service.getVersions(9L));
	}
}
