package com.tracelink.appsec.watchtower.core.cwe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import com.tracelink.appsec.watchtower.core.rule.CustomRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.rule.RuleState;

/** The curated starter CWE map: only for rules with no CWE, only with known CWEs, always previewed. */
class CweStarterMapServiceTest {
	private final List<CustomRuleDto> rules = new ArrayList<>();
	private RuleService ruleService;
	private CweCatalogService catalog;
	private CweStarterMapService service;

	private static final class StarterRule extends CustomRuleDto {
		private final String module;

		StarterRule(String module) {
			this.module = module;
		}

		@Override
		public String getModule() {
			return module;
		}

		@Override
		public RuleEntity toEntity() {
			throw new UnsupportedOperationException();
		}
	}

	@BeforeEach
	void setUp() {
		ruleService = mock(RuleService.class);
		when(ruleService.getRules()).thenAnswer(invocation -> List.copyOf(rules));
		catalog = mock(CweCatalogService.class);
		when(catalog.isLoaded()).thenReturn(true);
		service = new CweStarterMapService(ruleService, catalog);
	}

	private StarterRule rule(long id, String module, String name, String cwe) {
		StarterRule rule = new StarterRule(module);
		rule.setId(id);
		rule.setName(name);
		rule.getStewardship().setCwe(cwe);
		rules.add(rule);
		return rule;
	}

	private void known(String label, String name, String usage) {
		int id = Integer.parseInt(label.substring(4));
		when(catalog.find(label)).thenReturn(Optional.of(new CweEntry(id, name, "Base", "Simple", "Stable", usage, "d", null, List.of())));
	}

	@Test
	void theBundledMapIsWellFormed() {
		assertThat(service.mappedRuleCount()).isGreaterThanOrEqualTo(10);
		assertThat(service.moduleCwes()).containsEntry("betterleaks", "CWE-798");
	}

	@Test
	void aRuleWithoutACweGetsTheMappedOne() {
		rule(1, "pmd", "EmptyCatchBlock", null);
		known("CWE-390", "Detection of Error Condition Without Action", "Allowed");

		var preview = service.preview();

		assertThat(preview.proposals()).hasSize(1);
		assertThat(preview.proposals().get(0).ruleId()).isEqualTo(1);
		assertThat(preview.proposals().get(0).cwe()).isEqualTo("CWE-390");
		assertThat(preview.proposals().get(0).cweName()).isEqualTo("Detection of Error Condition Without Action");
	}

	@Test
	void aWholeModuleCanShareOneCwe() {
		rule(1, "betterleaks", "aws-access-token", null);
		rule(2, "betterleaks", "github-pat", null);
		known("CWE-798", "Use of Hard-coded Credentials", "Allowed");

		assertThat(service.preview().proposals()).extracting(CweStarterMapService.Proposal::ruleId).containsExactly(1L, 2L);
	}

	@Test
	void ruleThatAlreadyHasACweIsNotSecurityRetiredOrNotInTheMapAreLeftAlone() {
		rule(1, "pmd", "EmptyCatchBlock", "CWE-1");
		rule(2, "pmd", "CloseResource", null).getStewardship().setSecurityRelevance("NOT_SECURITY");
		rule(3, "pmd", "DoNotTerminateVM", null).getStewardship().setState(RuleState.RETIRED);
		rule(4, "pmd", "SomethingElse", null);
		rule(5, "eslint", "EmptyCatchBlock", null);
		known("CWE-390", "x", "Allowed");
		known("CWE-772", "y", "Allowed");
		known("CWE-382", "z", "Allowed");

		assertThat(service.preview().proposals()).isEmpty();
	}

	@Test
	void aMappedCweThatMitreNowDiscouragesOrDoesNotKnowIsSkippedAndCounted() {
		rule(1, "pmd", "EmptyCatchBlock", null);
		rule(2, "pmd", "CloseResource", null);
		known("CWE-390", "x", "Discouraged");
		when(catalog.find("CWE-772")).thenReturn(Optional.empty());

		var preview = service.preview();

		assertThat(preview.proposals()).isEmpty();
		assertThat(preview.skippedUnknownCwe()).isEqualTo(2);
	}

	@Test
	void nothingIsPreviewedOrAppliedBeforeTheCatalogIsLoaded() throws Exception {
		when(catalog.isLoaded()).thenReturn(false);
		rule(1, "pmd", "EmptyCatchBlock", null);

		assertThatThrownBy(() -> service.preview()).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("catalog");
		assertThatThrownBy(() -> service.apply("alice")).isInstanceOf(IllegalArgumentException.class);
		verify(ruleService, never()).applyCwes(anyMap(), any());
	}

	@Test
	@SuppressWarnings("unchecked")
	void applyingSendsTheProposalsInChunksOfAtMostOneHundred() throws Exception {
		for (long id = 1; id <= 230; id++) {
			rule(id, "betterleaks", "secret-" + id, null);
		}
		known("CWE-798", "Use of Hard-coded Credentials", "Allowed");
		when(ruleService.applyCwes(anyMap(), eq("alice"))).thenAnswer(invocation -> ((Map<Long, String>) invocation.getArgument(0)).size());

		int changed = service.apply("alice");

		ArgumentCaptor<Map<Long, String>> sent = ArgumentCaptor.forClass(Map.class);
		verify(ruleService, times(3)).applyCwes(sent.capture(), eq("alice"));
		assertThat(sent.getAllValues()).extracting(Map::size).containsExactly(100, 100, 30);
		assertThat(sent.getAllValues().get(0).values()).containsOnly("CWE-798");
		assertThat(changed).isEqualTo(230);
	}
}
