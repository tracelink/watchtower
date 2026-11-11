package com.tracelink.appsec.watchtower.core.rule;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.mock.MockRuleEntity;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.IRuleEditor;
import com.tracelink.appsec.watchtower.core.ruleset.ImportOption;

@ExtendWith({SpringExtension.class, MockitoExtension.class})
@MockitoSettings(strictness = Strictness.LENIENT)
public class RuleServiceTest {
	@Test
	public void startupObservesCurrentDefinitionsWithoutRepeatingOnCacheReads() {
		RuleRepository repository = Mockito.mock(RuleRepository.class);
		var history = Mockito.mock(com.tracelink.appsec.watchtower.core.rule.candidate.RuleDefinitionHistory.class);
		var baseline = new MockRuleEntity();
		BDDMockito.when(repository.findAll()).thenReturn(List.of(baseline));
		var service = new RuleService(repository);
		service.setDefinitionHistory(history);
		service.warmRuleCache();
		service.getRules();
		Mockito.verify(history, Mockito.times(1)).record(Mockito.any());
	}

	private static final String RULE_NAME = "Abstract Rule";

	@MockitoBean
	private RuleRepository ruleRepository;

	private RuleService ruleService;
	private RuleEntity rule;

	@Mock
	private IRuleEditor mockRuleManager;

	@BeforeEach
	public void setup() {
		ruleService = new RuleService(ruleRepository);
		rule = new MockRuleEntity();
		// RULE_NAME is what the "get by name"/"collision" tests below look up - RuleService
		// now resolves names against its in-memory cache (see RULE_CACHE_REFRESH_INTERVAL_MS)
		// rather than a direct findByName query, so rule's own name has to actually be
		// RULE_NAME for those lookups to find it.
		rule.setName(RULE_NAME);
	}


	@Test
	public void testGetRules() {
		RuleEntity rule2 = new MockRuleEntity();
		BDDMockito.when(ruleRepository.findAll()).thenReturn(Arrays.asList(rule, rule2));
		List<RuleDto> rules = ruleService.getRules();
		Assertions.assertEquals(2, rules.size());
		Assertions.assertEquals(rule.getName(), rules.get(0).getName());
		Assertions.assertEquals(rule.getMessage(), rules.get(0).getMessage());
		Assertions.assertEquals(rule2.getName(), rules.get(1).getName());
		Assertions.assertEquals(rule2.getMessage(), rules.get(1).getMessage());
	}

	@Test
	public void testGetRule() throws Exception {
		BDDMockito.when(ruleRepository.findAll()).thenReturn(Collections.singletonList(rule));
		Assertions.assertEquals(rule, ruleService.getRule(RULE_NAME));
	}

	@Test
	public void testGetRuleNotFound() throws Exception {
		Assertions.assertNull(ruleService.getRule(RULE_NAME));
	}

	@Test
	public void testGetRuleId() throws Exception {
		rule.setId(123L);
		BDDMockito.when(ruleRepository.findAll()).thenReturn(Collections.singletonList(rule));
		Assertions.assertEquals(rule, ruleService.getRule(123L));
	}

	@Test
	public void testGetRuleIdNotFound() throws Exception {
		Assertions.assertThrows(RuleNotFoundException.class,
				() -> {
					ruleService.getRule(123L);
				});
	}

	@Test
	public void testGetRulesForModule() {
		RuleEntity rule2 = new MockRuleEntity();
		rule2.setName("A");
		String scannerType = rule.toDto().getModule();
		BDDMockito.when(ruleRepository.findAll()).thenReturn(Arrays.asList(rule, rule2));
		List<RuleDto> rules = ruleService.getRulesForModule(scannerType);
		MatcherAssert.assertThat(rules, Matchers.hasSize(2));
		RuleDto[] rulesArr = rules.toArray(new RuleDto[2]);
		MatcherAssert.assertThat(rulesArr[0].getName(), Matchers.is(rule2.getName()));
		MatcherAssert.assertThat(rulesArr[1].getName(), Matchers.is(rule.getName()));
	}

	@Test
	public void testCountRulesByModuleIsLowerCaseKeyed() {
		RuleEntity rule2 = new MockRuleEntity();
		rule2.setName("A");
		String module = rule.toDto().getModule();
		BDDMockito.when(ruleRepository.findAll()).thenReturn(Arrays.asList(rule, rule2));
		MatcherAssert.assertThat(ruleService.countRulesByModule(),
				Matchers.hasEntry(module.toLowerCase(java.util.Locale.ROOT), 2L));
	}

	@Test
	public void testDeleteRule() throws Exception {
		// rule defaults to id 1L (MockRuleEntity's no-arg constructor).
		BDDMockito.when(ruleRepository.findById(1L)).thenReturn(java.util.Optional.of(rule));
		ruleService.deleteRule(1L);
		BDDMockito.verify(ruleRepository).delete(rule);
	}

	@Test
	public void deletingARuleUsesTheCurrentRowNotTheCachedCopy() throws Exception {
		// Dev E2E G03: a rule edited since the cache loaded could not be deleted (stale version).
		RuleEntity cachedCopy = new MockRuleEntity();
		RuleEntity currentRow = new MockRuleEntity();
		BDDMockito.when(ruleRepository.findAll()).thenReturn(Collections.singletonList(cachedCopy));
		BDDMockito.when(ruleRepository.findById(1L)).thenReturn(java.util.Optional.of(currentRow));

		ruleService.deleteRule(1L);

		BDDMockito.verify(ruleRepository).delete(currentRow);
		BDDMockito.verify(ruleRepository, BDDMockito.never()).delete(cachedCopy);
	}

	@Test
	public void aRuleThatChangedAfterAScanIsReportedFromTheHistory() {
		var history = org.mockito.Mockito.mock(
				com.tracelink.appsec.watchtower.core.rule.candidate.RuleDefinitionHistory.class);
		ruleService.setDefinitionHistory(history);
		BDDMockito.when(history.changedAfter(1L, 5000L)).thenReturn(true);

		Assertions.assertTrue(ruleService.changedAfter(rule, 5000L));
		Assertions.assertFalse(ruleService.changedAfter(rule, 9000L));
	}

	@Test
	public void withoutAHistoryNothingIsSaidToHaveChanged() {
		Assertions.assertFalse(ruleService.changedAfter(rule, 5000L));
	}

	@Test
	public void testDeleteRuleNotFound() throws Exception {
		Assertions.assertThrows(RuleNotFoundException.class,
				() -> {
					ruleService.deleteRule(1L);
				});
	}

	@Test
	public void testCreatesNameCollision() {
		BDDMockito.when(ruleRepository.findAll()).thenReturn(Collections.singletonList(rule));
		Assertions.assertTrue(ruleService.createsNameCollision(rule.getId() + 1, RULE_NAME));
	}

	@Test
	public void aNameDifferingOnlyInCaseCollides() {
		// MySQL's findByName matches it, so two such rules break later imports
		BDDMockito.when(ruleRepository.findAll()).thenReturn(Collections.singletonList(rule));
		Assertions.assertTrue(ruleService.createsNameCollision(rule.getId() + 1,
				RULE_NAME.toUpperCase(java.util.Locale.ROOT)));
		Assertions.assertSame(rule,
				ruleService.getRule(RULE_NAME.toLowerCase(java.util.Locale.ROOT)));
	}

	@Test
	public void testCreatesNameCollisionSameId() {
		BDDMockito.when(ruleRepository.findAll()).thenReturn(Collections.singletonList(rule));
		Assertions.assertFalse(ruleService.createsNameCollision(rule.getId(), RULE_NAME));
	}

	@Test
	public void testCreatesNameCollisionNoMatch() {
		Assertions.assertFalse(ruleService.createsNameCollision(1L, RULE_NAME));
	}

	@Test
	public void testImportRules() throws RuleException {
		String user = "jdoe";
		ruleService.importRules(Collections.singleton(rule.toDto()), user, ImportOption.OVERRIDE,
				ImportOption.OVERRIDE);

		ArgumentCaptor<Iterable<RuleEntity>> argumentCaptor =
				ArgumentCaptor.forClass(Iterable.class);
		BDDMockito.verify(ruleRepository, Mockito.times(1)).saveAll(argumentCaptor.capture());
		BDDMockito.verify(ruleRepository, Mockito.times(1)).flush();
		Set<RuleEntity> rules = (Set<RuleEntity>) argumentCaptor.getValue();
		Assertions.assertEquals(rule.getName(), rules.iterator().next().getName());
		Assertions.assertEquals(user, rules.iterator().next().getAuthor());
	}

	@Test
	public void testImportRulesFixAuthor() throws RuleException {
		String user = "jdoe2";
		rule.setAuthor(null);
		ruleService.importRules(Collections.singleton(rule.toDto()), user, ImportOption.OVERRIDE,
				ImportOption.OVERRIDE);

		ArgumentCaptor<Iterable<RuleEntity>> argumentCaptor =
				ArgumentCaptor.forClass(Iterable.class);
		BDDMockito.verify(ruleRepository, Mockito.times(1)).saveAll(argumentCaptor.capture());
		BDDMockito.verify(ruleRepository, Mockito.times(1)).flush();
		Set<RuleEntity> rules = (Set<RuleEntity>) argumentCaptor.getValue();
		Assertions.assertEquals(rule.getName(), rules.iterator().next().getName());
		Assertions.assertEquals(user, rules.iterator().next().getAuthor());
	}

	@Test
	public void testImportRulesRejectedByTheOwningModulesValidator() {
		// A module can require more than bean validation - e.g. that a custom secrets rule
		// really matches its sample - and an import must not bypass that.
		CustomRuleValidator validator = new CustomRuleValidator() {
			@Override
			public boolean supports(RuleDto candidate) {
				return true;
			}

			@Override
			public void validate(RuleDto candidate) throws RuleException {
				throw new RuleException("does not match its positive sample");
			}
		};
		ruleService.setCustomRuleValidators(List.of(validator));

		RuleException e = Assertions.assertThrows(RuleException.class,
				() -> ruleService.importRules(Collections.singleton(rule.toDto()), "foo",
						ImportOption.OVERRIDE, ImportOption.OVERRIDE));

		MatcherAssert.assertThat(e.getMessage(),
				Matchers.containsString("does not match its positive sample"));
		BDDMockito.verify(ruleRepository, BDDMockito.never()).saveAll(BDDMockito.any());
	}

	@Test
	public void testImportRulesIgnoresValidatorsForOtherModules() throws RuleException {
		CustomRuleValidator otherModule = new CustomRuleValidator() {
			@Override
			public boolean supports(RuleDto candidate) {
				return false;
			}

			@Override
			public void validate(RuleDto candidate) throws RuleException {
				throw new RuleException("should not be called");
			}
		};
		ruleService.setCustomRuleValidators(List.of(otherModule));

		ruleService.importRules(Collections.singleton(rule.toDto()), "foo",
				ImportOption.OVERRIDE, ImportOption.OVERRIDE);

		BDDMockito.verify(ruleRepository).saveAll(BDDMockito.any());
	}

	@Test
	public void testImportRulesFailValidation() {
		Throwable t = Assertions.assertThrows(RuleException.class, () -> {
			rule.setExternalUrl(null);
			ruleService.importRules(Collections.singleton(rule.toDto()), "foo",
					ImportOption.OVERRIDE, ImportOption.OVERRIDE);
		});
		Assertions.assertTrue(t.getMessage().contains("One or more rules are invalid"));
	}
}
