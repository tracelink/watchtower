package com.tracelink.appsec.watchtower.core.assistant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.access.AccessDeniedException;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.tracelink.appsec.watchtower.core.assistant.features.RuleDraftSuggestService;
import com.tracelink.appsec.watchtower.core.assistant.features.StructuredFeatureCall;
import com.tracelink.appsec.watchtower.core.cwe.CweCatalogService;
import com.tracelink.appsec.watchtower.core.cwe.CweEntry;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDraftData;
import com.tracelink.appsec.watchtower.core.rule.RuleDesignerService;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.rule.RuleStewardship;
import com.tracelink.appsec.watchtower.core.rule.draft.RuleDraftService;

/** The assistant drafts a rule for a gap: what it is asked, what it may choose, and what is kept. */
class RuleDraftSuggestServiceTest {
	private static final String DRAFT_ID = "5d1c5a0e-0000-4000-8000-000000000001";
	private StructuredFeatureCall calls;
	private AssistantAccess access;
	private CweCatalogService catalog;
	private RuleService rules;
	private RuleDesignerService designers;
	private RuleDraftService drafts;
	private RuleDraftSuggestService service;

	@BeforeEach
	void setUp() {
		calls = mock(StructuredFeatureCall.class);
		access = mock(AssistantAccess.class);
		catalog = mock(CweCatalogService.class);
		rules = mock(RuleService.class);
		designers = mock(RuleDesignerService.class);
		drafts = mock(RuleDraftService.class);
		when(calls.readiness(AssistantFeature.RULE_DRAFT)).thenReturn(new StructuredFeatureCall.Readiness(null, "Ready."));
		when(catalog.isLoaded()).thenReturn(true);
		known("CWE-89", "SQL Injection", "Allowed");
		when(designers.enabledDesigners()).thenReturn(Set.of("pmd", "regex", "opengrep", "eslint"));
		when(drafts.create(anyString(), any())).thenAnswer(invocation -> ((RuleDraftData) invocation.getArgument(1)).withId(DRAFT_ID));
		service = new RuleDraftSuggestService(calls, access, catalog, rules, designers, drafts);
	}

	private void known(String label, String name, String usage) {
		when(catalog.find(label)).thenReturn(Optional.of(new CweEntry(Integer.parseInt(label.substring(4)), name, "Base", "Simple", "Stable", usage,
				"Builds a query from user input without neutralising it.", null, List.of())));
	}

	private static String answer(String engine, int priority, String reason) {
		return "{\"engine\":\"" + engine + "\",\"reason\":\"" + reason + "\",\"name\":\"No string-built SQL\",\"message\":\"Use query parameters.\","
				+ "\"priority\":" + priority + ",\"definition\":\"//MethodCall\",\"file_extension\":\"\",\"vulnerable_example\":\"a\","
				+ "\"safe_example\":\"b\",\"rationale\":\"Looks for concatenation into a query.\"}";
	}

	private void model(String reply) {
		when(calls.ask(anyString(), eq(AssistantFeature.RULE_DRAFT), anyString(), anyString(), anyString(), any(ObjectNode.class), anyInt(), anyInt()))
				.thenReturn(Optional.ofNullable(reply));
	}

	private RuleDto ruleWithCwe(String name, String cwe) {
		var rule = mock(RuleDto.class);
		var stewardship = new RuleStewardship();
		stewardship.setCwe(cwe);
		when(rule.getStewardship()).thenReturn(stewardship);
		when(rule.getName()).thenReturn(name);
		return rule;
	}

	@Test
	void aGapBecomesAStoredDraftAndALinkToTheDesigner() {
		model(answer("pmd", 2, "PMD can see the call pattern in Java."));
		var existing = ruleWithCwe("Existing SQL rule", "CWE-89");
		when(rules.getRules()).thenReturn(List.of(existing));

		var result = service.suggest("alice", "cwe-89", "java");

		assertThat(result).containsEntry("state", "OK").containsEntry("engine", "pmd").containsEntry("reason", "PMD can see the call pattern in Java.")
				.containsEntry("url", "/designer/pmd?draft=" + DRAFT_ID).containsEntry("draft_id", DRAFT_ID);
		var stored = ArgumentCaptor.forClass(RuleDraftData.class);
		verify(drafts).create(eq("alice"), stored.capture());
		assertThat(stored.getValue().cwe()).isEqualTo("CWE-89");
		assertThat(stored.getValue().language()).isEqualTo("Java");
		assertThat(stored.getValue().priority()).isEqualTo(2);
		assertThat(stored.getValue().sourceLabel()).isEqualTo("Coverage gap: CWE-89 · Java / Spring (assistant draft)");
		verify(access).require("alice", "Assistant Use");
		verify(access).require("alice", "Rule Modify");
		verify(access).require("alice", "Rule Designer");
	}

	@Test
	void theModelSeesTheWeaknessTheLanguageTheScannersAndExistingRuleNamesAndNothingElse() {
		model(answer("regex", 3, "A pattern is enough here."));
		var sql = ruleWithCwe("Existing SQL rule", "CWE-89");
		var xss = ruleWithCwe("An XSS rule", "CWE-79");
		when(rules.getRules()).thenReturn(List.of(sql, xss));

		service.suggest("alice", "CWE-89", "PYTHON");

		var input = ArgumentCaptor.forClass(String.class);
		var maxIn = ArgumentCaptor.forClass(Integer.class);
		var maxOut = ArgumentCaptor.forClass(Integer.class);
		verify(calls).ask(eq("alice"), eq(AssistantFeature.RULE_DRAFT), anyString(), input.capture(), eq("rule_draft"), any(ObjectNode.class),
				maxIn.capture(), maxOut.capture());
		assertThat(input.getValue()).contains("CWE-89", "SQL Injection", "Python", "Existing SQL rule", "opengrep", "regex")
				.doesNotContain("An XSS rule", "\"pmd\"", "eslint");
		assertThat(maxIn.getValue()).isEqualTo(12000);
		assertThat(maxOut.getValue()).isEqualTo(3500);
		verify(calls).requireAffordable("alice", AssistantFeature.RULE_DRAFT, 12000, 3500);
	}

	@Test
	void onlyScannersThatAreOnAndCanScanTheLanguageAreOffered() {
		when(designers.enabledDesigners()).thenReturn(Set.of("regex", "eslint"));
		model(answer("regex", 3, "A pattern is enough here."));
		when(rules.getRules()).thenReturn(List.of());

		service.suggest("alice", "CWE-89", "JAVA");

		var input = ArgumentCaptor.forClass(String.class);
		verify(calls).ask(anyString(), any(), anyString(), input.capture(), anyString(), any(ObjectNode.class), anyInt(), anyInt());
		assertThat(input.getValue()).contains("\"scanner\":\"regex\"").doesNotContain("pmd", "opengrep", "eslint");
	}

	@Test
	void noScannerForTheLanguageMeansNoQuestion() {
		when(designers.enabledDesigners()).thenReturn(Set.of("eslint"));

		var result = service.suggest("alice", "CWE-89", "PYTHON");

		assertThat(result).containsEntry("state", "NO_ENGINE");
		assertThat((String) result.get("message")).contains("Python").contains("Scanner modules");
		verify(calls, never()).ask(anyString(), any(), anyString(), anyString(), anyString(), any(ObjectNode.class), anyInt(), anyInt());
	}

	@Test
	void aScannerThatWasNotOfferedMakesTheAnswerUnusable() {
		model(answer("eslint", 2, "ESLint would do."));
		when(rules.getRules()).thenReturn(List.of());

		var result = service.suggest("alice", "CWE-89", "JAVA");

		assertThat(result).containsEntry("state", "UNUSABLE");
		assertThat((String) result.get("message")).contains("not offered").contains("Nothing was saved");
		verify(drafts, never()).create(anyString(), any());
	}

	@Test
	void anAnswerWithABadPriorityOrAReasonThatLooksLikeASecretIsUnusable() {
		when(rules.getRules()).thenReturn(List.of());
		model(answer("pmd", 9, "Fine.").replace("\"priority\":9", "\"priority\":\"high\""));
		assertThat(service.suggest("alice", "CWE-89", "JAVA")).containsEntry("state", "UNUSABLE");
		model(answer("pmd", 2, "password = hunter2hunter2 would be seen."));
		assertThat(service.suggest("alice", "CWE-89", "JAVA")).containsEntry("state", "UNUSABLE");
		model("not json");
		assertThat(service.suggest("alice", "CWE-89", "JAVA")).containsEntry("state", "UNUSABLE");
		model(null);
		assertThat(service.suggest("alice", "CWE-89", "JAVA")).containsEntry("state", "UNUSABLE");
		verify(drafts, never()).create(anyString(), any());
	}

	@Test
	void aDraftTheStoreRefusesIsReportedWithOurOwnWordsNotTheModels() {
		model(answer("pmd", 2, "PMD can see the call pattern in Java."));
		when(rules.getRules()).thenReturn(List.of());
		doThrow(new IllegalArgumentException("The rule looks like it contains a secret, so it was not stored.")).when(drafts).create(anyString(), any());

		var result = service.suggest("alice", "CWE-89", "JAVA");

		assertThat(result).containsEntry("state", "UNUSABLE");
		assertThat((String) result.get("message")).startsWith("The rule looks like it contains a secret");
	}

	@Test
	void secretWeaknessesAreNeverDraftedAndNothingIsAsked() {
		for (String secret : new String[] { "CWE-798", "259", "cwe-321", "CWE-522" }) {
			assertThat(service.suggest("alice", secret, "JAVA")).containsEntry("state", "BLOCKED");
		}
		verify(calls, never()).ask(anyString(), any(), anyString(), anyString(), anyString(), any(ObjectNode.class), anyInt(), anyInt());
		verify(drafts, never()).create(anyString(), any());
	}

	@Test
	void theWeaknessAndLanguageAreChecked() {
		assertThatThrownBy(() -> service.suggest("alice", "not a cwe", "JAVA")).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("CWE-89");
		assertThatThrownBy(() -> service.suggest("alice", "CWE-99999", "JAVA")).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("catalog");
		known("CWE-74", "Injection", "Discouraged");
		assertThatThrownBy(() -> service.suggest("alice", "CWE-74", "JAVA")).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> service.suggest("alice", "CWE-89", "OTHER")).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("Java, Python");
		assertThatThrownBy(() -> service.suggest("alice", "CWE-89", null)).isInstanceOf(IllegalArgumentException.class);
		when(catalog.isLoaded()).thenReturn(false);
		assertThatThrownBy(() -> service.suggest("alice", "CWE-89", "JAVA")).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("catalog");
	}

	@Test
	void aSwitchThatIsOffOrMissingGrantsStopsEverything() {
		when(calls.readiness(AssistantFeature.RULE_DRAFT)).thenReturn(new StructuredFeatureCall.Readiness("OFF", "Rule drafts is off."));
		assertThat(service.suggest("alice", "CWE-89", "JAVA")).containsEntry("state", "OFF").containsEntry("message", "Rule drafts is off.");

		doThrow(new AccessDeniedException("no")).when(access).require("bob", "Rule Designer");
		assertThatThrownBy(() -> service.suggest("bob", "CWE-89", "JAVA")).isInstanceOf(AccessDeniedException.class);
		verify(calls, never()).ask(anyString(), any(), anyString(), anyString(), anyString(), any(ObjectNode.class), anyInt(), anyInt());
	}

	@Test
	void theResultCarriesOnlyWhatThePageNeeds() {
		model(answer("pmd", 2, "PMD can see the call pattern in Java."));
		when(rules.getRules()).thenReturn(List.of());

		Map<String, Object> result = service.suggest("alice", "CWE-89", "JAVA");

		assertThat(result.keySet()).containsExactlyInAnyOrder("state", "draft_id", "engine", "reason", "url");
	}
}
