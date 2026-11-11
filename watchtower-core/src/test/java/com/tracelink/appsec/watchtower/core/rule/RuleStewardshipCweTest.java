package com.tracelink.appsec.watchtower.core.rule;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import com.tracelink.appsec.watchtower.core.mock.MockRuleEntity;

/** A rule's primary and secondary CWEs, and the "not a security rule" outcome. */
class RuleStewardshipCweTest {
	private RuleRepository repository;
	private RuleStewardshipHistoryRepository history;
	private RuleService service;
	private MockRuleEntity rule;

	@BeforeEach
	void setUp() {
		repository = mock(RuleRepository.class);
		history = mock(RuleStewardshipHistoryRepository.class);
		service = new RuleService(repository);
		service.setStewardshipHistoryRepository(history);
		rule = new MockRuleEntity();
		when(repository.findById(rule.getId())).thenReturn(Optional.of(rule));
	}

	private RuleStewardshipUpdate update(String cwe, String secondary, boolean notSecurity) {
		return new RuleStewardshipUpdate(RuleState.ACTIVE, "owner", null, cwe, secondary, notSecurity, null);
	}

	private void save(RuleStewardshipUpdate update) throws Exception {
		service.updateStewardship(rule.getId(), rule.toDto().getModule(), update, "editor");
	}

	private MockRuleEntity ruleWithId(long id, String cwe) {
		MockRuleEntity other = new MockRuleEntity();
		other.setId(id);
		other.getStewardship().setCwe(cwe);
		return other;
	}

	@SuppressWarnings("unchecked")
	private void knowRules(MockRuleEntity... rules) {
		when(repository.findAllById(any())).thenAnswer(invocation -> {
			Set<Long> wanted = new HashSet<>();
			((Iterable<Long>) invocation.getArgument(0)).forEach(wanted::add);
			return Arrays.stream(rules).filter(r -> wanted.contains(r.getId())).toList();
		});
	}

	@Test
	void secondaryCwesAreNormalisedAndSavedWithTheHistoryRow() throws Exception {
		save(update("CWE-89", " cwe-564 , CWE-943 ", false));

		assertEquals("CWE-89", rule.getStewardship().getCwe());
		assertEquals("CWE-564,CWE-943", rule.getStewardship().getSecondaryCwes());
		assertNull(rule.getStewardship().getSecurityRelevance());
		ArgumentCaptor<RuleStewardshipHistoryEntity> saved = ArgumentCaptor.forClass(RuleStewardshipHistoryEntity.class);
		verify(history).saveAndFlush(saved.capture());
		assertEquals("CWE-564,CWE-943", saved.getValue().getStewardship().getSecondaryCwes());
	}

	@Test
	void rejectsSecondaryCwesThatAreMalformedRepeatedOrTooMany() {
		for (String bad : List.of("CWE-1;CWE-2", "564", "CWE-564,CWE-564", "CWE-89",
				"CWE-1,CWE-2,CWE-3,CWE-4,CWE-5,CWE-6,CWE-7,CWE-8,CWE-9,CWE-10,CWE-11")) {
			assertThrows(RuleException.class, () -> save(update("CWE-89", bad, false)), bad);
		}
		verify(repository, never()).saveAndFlush(any());
	}

	@Test
	void secondaryCwesNeedAPrimaryOne() {
		assertThrows(RuleException.class, () -> save(update(null, "CWE-564", false)));
	}

	@Test
	void aRuleCanBeMarkedNotASecurityRuleOnlyWhenItHasNoCwe() throws Exception {
		assertThrows(RuleException.class, () -> save(update("CWE-89", null, true)));
		assertThrows(RuleException.class, () -> save(update(null, "CWE-564", true)));

		save(update(null, null, true));

		assertTrue(rule.getStewardship().isNotSecurity());
		assertEquals(RuleStewardship.NOT_SECURITY, rule.getStewardship().getSecurityRelevance());
	}

	@Test
	void givingTheRuleACweAgainClearsTheNotASecurityRuleMark() throws Exception {
		rule.getStewardship().setSecurityRelevance(RuleStewardship.NOT_SECURITY);

		save(update("CWE-79", null, false));

		assertFalse(rule.getStewardship().isNotSecurity());
		assertNull(rule.getStewardship().getSecurityRelevance());
	}

	@Test
	void theOldFiveValueConstructorStillMeansNoSecondaryCwesAndASecurityRule() throws Exception {
		save(new RuleStewardshipUpdate(RuleState.ACTIVE, "owner", null, "CWE-79", null));

		assertNull(rule.getStewardship().getSecondaryCwes());
		assertNull(rule.getStewardship().getSecurityRelevance());
	}

	@Test
	void applySuggestionsSetsCwesAndMarksStyleRulesInOneChange() throws Exception {
		MockRuleEntity web = ruleWithId(31, null);
		MockRuleEntity style = ruleWithId(32, null);
		MockRuleEntity taken = ruleWithId(33, "CWE-89");
		MockRuleEntity styleWithCwe = ruleWithId(34, "CWE-89");
		knowRules(web, style, taken, styleWithCwe);
		Map<Long, String> cwes = new LinkedHashMap<>();
		cwes.put(31L, "CWE-79");
		cwes.put(33L, "CWE-79");

		int changed = service.applySuggestions(cwes, List.of(32L, 34L), "editor");

		assertEquals(2, changed, "one rule gained a CWE and one was marked; rules that already had a CWE are left alone");
		assertEquals("CWE-79", web.getStewardship().getCwe());
		assertTrue(style.getStewardship().isNotSecurity());
		assertEquals("CWE-89", taken.getStewardship().getCwe());
		assertEquals("CWE-89", styleWithCwe.getStewardship().getCwe());
		assertFalse(styleWithCwe.getStewardship().isNotSecurity());
		verify(history, times(2)).saveAllAndFlush(any());
	}

	@Test
	void theBulkFormCanMarkSeveralRulesAsNotSecurityRulesAndSkipsOnesThatHaveACwe() throws Exception {
		MockRuleEntity style = ruleWithId(61, null);
		MockRuleEntity alsoStyle = ruleWithId(62, " ");
		MockRuleEntity secure = ruleWithId(63, "CWE-79");
		knowRules(style, alsoStyle, secure);

		int changed = service.setOwnerAndCwe(List.of(61L, 62L, 63L), "appsec", "", true, "editor");

		assertEquals(2, changed);
		assertTrue(style.getStewardship().isNotSecurity());
		assertTrue(alsoStyle.getStewardship().isNotSecurity());
		assertEquals("appsec", style.getStewardship().getOwner());
		assertFalse(secure.getStewardship().isNotSecurity());
		assertNull(secure.getStewardship().getOwner(), "a rule that has a CWE is not touched by the not-a-security-rule change");
	}

	@Test
	void theBulkFormRefusesACweTogetherWithNotASecurityRule() {
		knowRules(ruleWithId(71, null));

		assertThrows(RuleException.class, () -> service.setOwnerAndCwe(List.of(71L), "", "CWE-79", true, "editor"));
	}

	@Test
	void settingACweInBulkClearsTheNotASecurityMark() throws Exception {
		MockRuleEntity style = ruleWithId(81, null);
		style.getStewardship().setSecurityRelevance(RuleStewardship.NOT_SECURITY);
		knowRules(style);

		service.setOwnerAndCwe(List.of(81L), "", "CWE-79", false, "editor");

		assertFalse(style.getStewardship().isNotSecurity());
		assertEquals("CWE-79", style.getStewardship().getCwe());
	}

	@Test
	void applySuggestionsChecksEveryCweBeforeChangingAnything() {
		MockRuleEntity first = ruleWithId(41, null);
		knowRules(first);

		assertThrows(RuleException.class, () -> service.applySuggestions(Map.of(41L, "79"), List.of(), "editor"));

		assertNull(first.getStewardship().getCwe());
		verify(repository, never()).saveAllAndFlush(any());
	}

	@Test
	void applySuggestionsRefusesARuleListedAsBothAWeaknessAndNotASecurityRule() {
		MockRuleEntity first = ruleWithId(51, null);
		knowRules(first);

		assertThrows(RuleException.class, () -> service.applySuggestions(Map.of(51L, "CWE-79"), List.of(51L), "editor"));
	}
}
