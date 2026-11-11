package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import com.tracelink.appsec.watchtower.core.assistant.features.CweSuggestService;
import com.tracelink.appsec.watchtower.core.assistant.features.StructuredFeatureCall;
import com.tracelink.appsec.watchtower.core.cwe.CweCatalogService;
import com.tracelink.appsec.watchtower.core.cwe.CweEntry;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.rule.RuleStewardship;

/** CWE suggestions checked against the MITRE catalog: a shortlist in, only real and usable CWEs out. */
class CweSuggestCatalogTest {
	private StructuredFeatureCall calls;
	private RuleService rules;
	private CweCatalogService catalog;
	private CweSuggestService service;

	@BeforeEach
	void setUp() throws Exception {
		calls = mock(StructuredFeatureCall.class);
		rules = mock(RuleService.class);
		catalog = mock(CweCatalogService.class);
		when(calls.readiness(AssistantFeature.CWE_SUGGEST)).thenReturn(new StructuredFeatureCall.Readiness(null, "Ready."));
		service = new CweSuggestService(calls, rules, mock(AssistantAccess.class), mock(AssistantSecretFindings.class), catalog);
		when(catalog.isLoaded()).thenReturn(true);
		when(catalog.shortlist(anyString(), anyInt())).thenReturn(List.of(entry(89, "SQL Injection"), entry(564, "SQL Injection: Hibernate")));
		when(catalog.isUsable("CWE-79")).thenReturn(true);
		when(catalog.isUsable("CWE-89")).thenReturn(true);
		when(catalog.isUsable("CWE-74")).thenReturn(false);
		when(catalog.name("CWE-79")).thenReturn("CWE-79 · Cross-site Scripting");
		when(catalog.name("CWE-89")).thenReturn("CWE-89 · SQL Injection");
		rule(1, "AvoidConcatenatedSql", "Builds SQL from strings");
		rule(2, "array-bracket-spacing", "Enforces spacing in brackets");
	}

	private static CweEntry entry(int id, String name) {
		return new CweEntry(id, name, "Base", "Simple", "Stable", "Allowed", "Description of " + name, null, List.of());
	}

	private void rule(long id, String name, String message) throws Exception {
		RuleEntity rule = mock(RuleEntity.class);
		RuleDto dto = mock(RuleDto.class);
		RuleStewardship stewardship = mock(RuleStewardship.class);
		when(dto.getModule()).thenReturn("pmd");
		when(rule.getId()).thenReturn(id);
		when(rule.getName()).thenReturn(name);
		when(rule.getMessage()).thenReturn(message);
		when(rule.getPriority()).thenReturn(RulePriority.MEDIUM);
		when(rule.getStewardship()).thenReturn(stewardship);
		when(rule.toDto()).thenReturn(dto);
		when(rules.getRule(id)).thenReturn(rule);
	}

	private static String item(long id, String outcome, String cwe, String reason) {
		return "{\"rule_id\":" + id + ",\"outcome\":\"" + outcome + "\",\"cwe\":\"" + cwe + "\",\"reason\":\"" + reason
				+ "\",\"confidence\":\"high\"}";
	}

	private void model(String... items) {
		when(calls.ask(anyString(), eq(AssistantFeature.CWE_SUGGEST), anyString(), anyString(), anyString(), any()))
				.thenReturn(Optional.of("{\"suggestions\":[" + String.join(",", items) + "]}"));
	}

	@SuppressWarnings("unchecked")
	private static List<Map<String, Object>> suggestions(Map<String, Object> result) {
		return (List<Map<String, Object>>) result.get("suggestions");
	}

	@Test
	void eachRuleIsSentWithAShortlistFromTheCatalog() {
		model();

		service.suggest("editor", List.of(1L));

		ArgumentCaptor<String> input = ArgumentCaptor.forClass(String.class);
		verify(calls).ask(anyString(), eq(AssistantFeature.CWE_SUGGEST), anyString(), input.capture(), anyString(), any());
		assertTrue(input.getValue().contains("\"candidates\""));
		assertTrue(input.getValue().contains("CWE-89"));
		assertTrue(input.getValue().contains("SQL Injection: Hibernate"));
		verify(catalog).shortlist(org.mockito.ArgumentMatchers.contains("AvoidConcatenatedSql"), anyInt());
	}

	@Test
	void anInventedOrDiscouragedCweIsDroppedAndARealOneGetsItsName() {
		model(item(1, "cwe", "CWE-99999", "Not in the catalog."), item(2, "cwe", "CWE-74", "Discouraged by MITRE."));
		var dropped = service.suggest("editor", List.of(1L, 2L));
		assertTrue(suggestions(dropped).isEmpty());

		model(item(1, "cwe", "CWE-89", "It builds SQL from strings."));
		var kept = service.suggest("editor", List.of(1L));
		assertEquals(1, suggestions(kept).size());
		assertEquals("CWE-89 · SQL Injection", suggestions(kept).get(0).get("cwe_name"));
		assertEquals("cwe", suggestions(kept).get(0).get("outcome"));
		assertEquals(true, kept.get("catalog"));
	}

	@Test
	void aStyleRuleCanBeAnsweredAsNotASecurityRule() {
		model(item(2, "not_security", "", "A formatting rule, not a weakness."));

		var result = service.suggest("editor", List.of(2L));

		assertEquals(1, suggestions(result).size());
		assertEquals("not_security", suggestions(result).get(0).get("outcome"));
		assertEquals("", suggestions(result).get(0).get("cwe"));
	}

	@Test
	void anAnswerOfUnknownOrACweOutcomeWithoutACweIsNotKept() {
		model(item(1, "unknown", "", "Cannot tell."), item(2, "cwe", "", "Forgot to name one."));

		var result = service.suggest("editor", List.of(1L, 2L));

		assertTrue(suggestions(result).isEmpty());
		assertEquals(2, ((Map<?, ?>) result.get("skipped")).get("unanswered"));
	}

	@Test
	void aNotASecurityRuleAnswerMustNotNameACwe() {
		model(item(2, "not_security", "CWE-79", "Contradicts itself."));

		assertTrue(suggestions(service.suggest("editor", List.of(2L))).isEmpty());
	}

	@Test
	void withoutALoadedCatalogOnlyTheShapeIsCheckedAndTheResultSaysSo() {
		when(catalog.isLoaded()).thenReturn(false);
		model(item(1, "cwe", "CWE-99999", "Cannot be checked."));

		var result = service.suggest("editor", List.of(1L));

		assertEquals(1, suggestions(result).size());
		assertEquals(false, result.get("catalog"));
		assertFalse(suggestions(result).get(0).containsKey("cwe_name"));
		verify(catalog, never()).shortlist(anyString(), anyInt());
	}
}
