package com.tracelink.appsec.watchtower.core.rule;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import com.tracelink.appsec.watchtower.core.mock.MockRuleEntity;
import com.tracelink.appsec.watchtower.core.ruleset.ImportOption;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;

class RuleStewardshipTest {
	private RuleRepository repository;
	private RuleStewardshipHistoryRepository history;
	private RuleService service;
	private MockRuleEntity existing;

	@BeforeEach
	void setup() {
		repository = mock(RuleRepository.class);
		history = mock(RuleStewardshipHistoryRepository.class);
		service = new RuleService(repository);
		service.setStewardshipHistoryRepository(history);
		existing = new MockRuleEntity();
		existing.getStewardship().setOwner("security-team");
		existing.getStewardship().setState(RuleState.DEPRECATED);
		existing.getStewardship().setCreatedAt(null);
		when(repository.findById(existing.getId())).thenReturn(Optional.of(existing));
		when(repository.findAll()).thenReturn(List.of(existing));
	}

	@Test
	void updateUsesOnlyEditableFieldsAndAuditsTheActor() throws Exception {
		existing.getStewardship().setOriginKey("upstream-identifier");
		existing.getStewardship().setRevision("a".repeat(64));
		service.updateStewardship(existing.getId(), existing.toDto().getModule(),
				new RuleStewardshipUpdate(RuleState.ACTIVE, " new-owner ",
						LocalDate.of(2026, 12, 1), "CWE-79", "Web"), "reviewer");
		assertEquals("new-owner", existing.getStewardship().getOwner());
		assertEquals("upstream-identifier", existing.getStewardship().getOriginKey());
		assertEquals("a".repeat(64), existing.getStewardship().getRevision());
		assertNull(existing.getStewardship().getCreatedAt());
		ArgumentCaptor<RuleStewardshipHistoryEntity> saved = ArgumentCaptor.forClass(RuleStewardshipHistoryEntity.class);
		verify(history).saveAndFlush(saved.capture());
		assertEquals("reviewer", saved.getValue().getChangedBy());
		existing.getStewardship().setOwner("changed-later");
		assertEquals("new-owner", saved.getValue().getStewardship().getOwner());
	}

	@Test
	void rejectsInvalidMetadataAndWrongModuleBeforeWriting() {
		assertThrows(RuleException.class, () -> service.updateStewardship(existing.getId(), "other",
				new RuleStewardshipUpdate(RuleState.RETIRED, null, null, null, null), "reviewer"));
		assertThrows(RuleException.class, () -> service.updateStewardship(existing.getId(), existing.toDto().getModule(),
				new RuleStewardshipUpdate(RuleState.RETIRED, null, null, "invalid", null), "reviewer"));
		verify(repository, never()).saveAndFlush(any());
		verifyNoInteractions(history);
		assertEquals(RuleState.DEPRECATED, existing.getStewardship().getState());
	}

	@Test
	void upstreamRetirementKeepsIdentityMembershipAndOnlyAuditsOnce() throws Exception {
		existing.getRulesets().add(new RulesetEntity());
		service.retireRule(existing.getId());
		service.retireRule(existing.getId());
		assertEquals(RuleState.RETIRED, existing.getStewardship().getState());
		assertEquals(1, existing.getRulesets().size());
		verify(repository, never()).delete(any());
		verify(history, times(1)).saveAndFlush(any());
	}

	private MockRuleEntity ruleWithId(long id, String cwe) {
		MockRuleEntity rule = new MockRuleEntity();
		rule.setId(id);
		rule.getStewardship().setCwe(cwe);
		return rule;
	}

	private void knowRules(MockRuleEntity... rules) {
		when(repository.findAllById(any())).thenAnswer(invocation -> {
			Set<Long> wanted = new java.util.HashSet<>();
			((Iterable<Long>) invocation.getArgument(0)).forEach(wanted::add);
			return java.util.Arrays.stream(rules).filter(rule -> wanted.contains(rule.getId())).toList();
		});
	}

	@Test
	void applyCwesFillsOnlyRulesWithoutOneAndWritesAHistoryRowEach() throws Exception {
		MockRuleEntity first = ruleWithId(11, null);
		MockRuleEntity second = ruleWithId(12, " ");
		MockRuleEntity taken = ruleWithId(13, "CWE-89");
		knowRules(first, second, taken);
		java.util.Map<Long, String> chosen = new java.util.LinkedHashMap<>();
		chosen.put(11L, "CWE-79");
		chosen.put(12L, "CWE-352");
		chosen.put(13L, "CWE-79");

		int changed = service.applyCwes(chosen, "editor");

		assertEquals(2, changed, "the rule that already had a CWE is skipped, not replaced");
		assertEquals("CWE-79", first.getStewardship().getCwe());
		assertEquals("CWE-352", second.getStewardship().getCwe());
		assertEquals("CWE-89", taken.getStewardship().getCwe());
		ArgumentCaptor<Iterable<RuleStewardshipHistoryEntity>> rows = ArgumentCaptor.forClass(Iterable.class);
		verify(history, times(2)).saveAllAndFlush(rows.capture());
	}

	@Test
	void applyCwesChecksEveryCweBeforeChangingAnything() {
		MockRuleEntity first = ruleWithId(21, null);
		MockRuleEntity second = ruleWithId(22, null);
		knowRules(first, second);
		java.util.Map<Long, String> chosen = new java.util.LinkedHashMap<>();
		chosen.put(21L, "CWE-79");
		chosen.put(22L, "79");

		assertThrows(RuleException.class, () -> service.applyCwes(chosen, "editor"));

		assertNull(first.getStewardship().getCwe(), "an invalid choice stops the whole batch");
		verify(repository, never()).saveAllAndFlush(any());
	}

	@Test
	void applyCwesRefusesMissingRulesAndBadSizes() {
		knowRules(ruleWithId(31, null));
		java.util.Map<Long, String> missing = new java.util.LinkedHashMap<>();
		missing.put(31L, "CWE-79");
		missing.put(32L, "CWE-79");
		assertThrows(com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException.class,
				() -> service.applyCwes(missing, "editor"));
		assertThrows(RuleException.class, () -> service.applyCwes(java.util.Map.of(), "editor"));
		java.util.Map<Long, String> tooMany = new java.util.LinkedHashMap<>();
		for (long id = 1; id <= RuleService.MAX_BULK_STEWARDSHIP + 1; id++) {
			tooMany.put(id, "CWE-79");
		}
		assertThrows(RuleException.class, () -> service.applyCwes(tooMany, "editor"));
	}

	@Test
	void retiredRulesAreExcludedThroughInheritanceWhileDeprecatedRulesRun() {
		MockRuleEntity retired = new MockRuleEntity();
		retired.setName("Retired");
		retired.getStewardship().setState(RuleState.RETIRED);
		RulesetDto parent = new RulesetDto();
		parent.getRules().add(retired.toDto());
		RulesetDto child = new RulesetDto();
		child.getRulesets().add(parent);
		child.getRules().add(existing.toDto());
		assertEquals(Set.of(existing.toDto()), child.getAllRules());
		assertEquals(1, parent.getRules().size(), "Retirement must preserve membership/history");
	}

	@Test
	void bothImportOverwritePathsPreserveStewardshipAndMembership() throws Exception {
		for (boolean provided : List.of(false, true)) {
			MockRuleEntity original = new MockRuleEntity(provided);
			original.getStewardship().setState(RuleState.RETIRED);
			original.getStewardship().setOwner("local-owner");
			original.setPersistenceVersion(7);
			original.getRulesets().add(new RulesetEntity());
			when(repository.findByName(original.getName())).thenReturn(original);
			doAnswer(call -> {
				Iterable<RuleEntity> rows = call.getArgument(0);
				RuleEntity imported = rows.iterator().next();
				assertEquals(original.getId(), imported.getId());
				assertEquals(7, imported.getPersistenceVersion());
				assertEquals("local-owner", imported.getStewardship().getOwner());
				assertEquals(RuleState.RETIRED, imported.getStewardship().getState());
				assertEquals(original.getRulesets(), imported.getRulesets());
				assertNull(imported.getStewardship().getCreatedAt());
				return List.of(imported);
			}).when(repository).saveAll(any());
			service.importRules(Set.of(original.toDto()), "importer", ImportOption.OVERRIDE, ImportOption.OVERRIDE);
		}
	}

	@Test
	void newImportsIgnoreTheExportedInstallationsNumericId() throws Exception {
		when(repository.saveAll(any())).thenAnswer(call -> {
			Iterable<RuleEntity> rows = call.getArgument(0);
			RuleEntity imported = rows.iterator().next();
			assertEquals(0, imported.getId());
			assertNull(imported.getStewardship().getOwner());
			return List.of(imported);
		});
		service.importRules(Set.of(existing.toDto()), "importer", ImportOption.OVERRIDE, ImportOption.OVERRIDE);
	}
}
