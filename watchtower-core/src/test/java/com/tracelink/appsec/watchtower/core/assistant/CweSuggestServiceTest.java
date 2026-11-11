package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
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
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.assistant.features.CweSuggestService;
import com.tracelink.appsec.watchtower.core.assistant.features.StructuredFeatureCall;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.rule.RuleStewardship;

class CweSuggestServiceTest {
	StructuredFeatureCall calls;
	RuleService rules;
	AssistantAccess access;
	AssistantSecretFindings secrets;
	CweSuggestService service;

	@BeforeEach
	void setup() {
		calls = mock(StructuredFeatureCall.class);
		rules = mock(RuleService.class);
		access = mock(AssistantAccess.class);
		secrets = mock(AssistantSecretFindings.class);
		when(calls.readiness(AssistantFeature.CWE_SUGGEST)).thenReturn(new StructuredFeatureCall.Readiness(null, "Ready."));
		service = new CweSuggestService(calls, rules, access, secrets);
	}

	RuleEntity rule(long id, String name, String message, String cwe, boolean secret) throws Exception {
		RuleEntity rule = mock(RuleEntity.class);
		RuleDto dto = mock(RuleDto.class);
		RuleStewardship stewardship = mock(RuleStewardship.class);
		when(stewardship.getCwe()).thenReturn(cwe);
		when(dto.getModule()).thenReturn("regex");
		when(rule.getId()).thenReturn(id);
		when(rule.getName()).thenReturn(name);
		when(rule.getMessage()).thenReturn(message);
		when(rule.getPriority()).thenReturn(RulePriority.MEDIUM);
		when(rule.getStewardship()).thenReturn(stewardship);
		when(rule.toDto()).thenReturn(dto);
		when(secrets.isSecretRule(dto)).thenReturn(secret);
		when(rules.getRule(id)).thenReturn(rule);
		return rule;
	}

	static String answer(String... items) {
		return "{\"suggestions\":[" + String.join(",", items) + "]}";
	}

	static String item(long id, String cwe, String reason, String confidence) {
		return "{\"rule_id\":" + id + ",\"cwe\":\"" + cwe + "\",\"reason\":\"" + reason + "\",\"confidence\":\"" + confidence + "\"}";
	}

	@SuppressWarnings("unchecked")
	Map<String, Object> skipped(Map<String, Object> result) {
		return (Map<String, Object>) result.get("skipped");
	}

	@Test
	void suggestsOnlyForRulesWithoutACweAndNeverSendsSecretOrAlreadySetRules() throws Exception {
		rule(1, "Unescaped output", "Writes user input into HTML", null, false);
		rule(2, "Already classified rule", "Has one", "CWE-89", false);
		rule(3, "Hardcoded key finder", "Finds keys", null, true);
		when(rules.getRule(4L)).thenThrow(new RuleNotFoundException(null));
		when(calls.ask(anyString(), eq(AssistantFeature.CWE_SUGGEST), anyString(), anyString(), anyString(), any()))
				.thenReturn(Optional.of(answer(item(1, "CWE-79", "It writes input into a page.", "high"),
						item(99, "CWE-79", "A rule that was never sent.", "high"))));

		var result = service.suggest("editor", List.of(1L, 2L, 3L, 4L));

		assertEquals("OK", result.get("state"));
		var suggestions = (List<?>) result.get("suggestions");
		assertEquals(1, suggestions.size());
		assertEquals("CWE-79", ((Map<?, ?>) suggestions.get(0)).get("cwe"));
		assertEquals(Map.of("secret", 1, "already_set", 1, "missing", 1, "unanswered", 0), skipped(result));
		ArgumentCaptor<String> input = ArgumentCaptor.forClass(String.class);
		verify(calls).ask(eq("editor"), eq(AssistantFeature.CWE_SUGGEST), anyString(), input.capture(), anyString(), any());
		assertTrue(input.getValue().contains("Unescaped output"));
		assertFalse(input.getValue().contains("Hardcoded key finder"), "secret rules are never sent");
		assertFalse(input.getValue().contains("Already classified rule"), "rules that have a CWE are not sent");
	}

	@Test
	void dropsMalformedDuplicateAndSecretLookingAnswers() throws Exception {
		for (long id = 1; id <= 5; id++) {
			rule(id, "Rule " + id, "Message", null, false);
		}
		when(calls.ask(anyString(), eq(AssistantFeature.CWE_SUGGEST), anyString(), anyString(), anyString(), any()))
				.thenReturn(Optional.of(answer(
						item(1, "79", "Missing the CWE prefix.", "high"),
						item(2, "CWE-0", "Zero is not a CWE number.", "high"),
						item(3, "CWE-79", "Confidence is not one of the allowed words.", "certain"),
						item(4, "CWE-79", "password = hunter2 leaked into the reason", "high"),
						item(5, "CWE-352", "Valid.", "low"),
						item(5, "CWE-79", "Duplicate of a rule already answered.", "high"))));

		var result = service.suggest("editor", List.of(1L, 2L, 3L, 4L, 5L));

		var suggestions = (List<?>) result.get("suggestions");
		assertEquals(1, suggestions.size());
		assertEquals(5L, ((Map<?, ?>) suggestions.get(0)).get("rule_id"));
		assertEquals("CWE-352", ((Map<?, ?>) suggestions.get(0)).get("cwe"));
		assertEquals(4, skipped(result).get("unanswered"));
	}

	@Test
	void keepsAPlainReasonThatRunsALittlePastTheRequestedLengthButNotAnAbsurdOne() throws Exception {
		rule(1, "Rule 1", "Message", null, false);
		rule(2, "Rule 2", "Message", null, false);
		String longer = "It writes request input straight into an HTML page without escaping it, which lets an attacker run script in another person's browser session. ".repeat(2).substring(0, 200);
		when(calls.ask(anyString(), eq(AssistantFeature.CWE_SUGGEST), anyString(), anyString(), anyString(), any()))
				.thenReturn(Optional.of(answer(item(1, "CWE-79", longer, "high"), item(2, "CWE-79", "x".repeat(300), "high"))));

		var result = service.suggest("editor", List.of(1L, 2L));

		var suggestions = (List<?>) result.get("suggestions");
		assertEquals(1, suggestions.size(), "models overshoot a 160-character ask; a plain 200-character reason is still useful");
		assertEquals(1L, ((Map<?, ?>) suggestions.get(0)).get("rule_id"));
		assertEquals(1, skipped(result).get("unanswered"), "an absurdly long reason is still dropped");
	}

	@Test
	void withholdsRuleTextThatLooksLikeASecret() throws Exception {
		rule(1, "Token finder", "Example: password = hunter2 and sk-abcdefghijklmnop1234", null, false);
		when(calls.ask(anyString(), eq(AssistantFeature.CWE_SUGGEST), anyString(), anyString(), anyString(), any()))
				.thenReturn(Optional.empty());

		service.suggest("editor", List.of(1L));

		ArgumentCaptor<String> input = ArgumentCaptor.forClass(String.class);
		verify(calls).ask(anyString(), eq(AssistantFeature.CWE_SUGGEST), anyString(), input.capture(), anyString(), any());
		assertFalse(input.getValue().contains("hunter2"));
		assertFalse(input.getValue().contains("sk-abcdefghijklmnop1234"));
		assertTrue(input.getValue().contains("withheld"));
	}

	@Test
	void keepsEarlierSuggestionsWhenTheDailyShareRunsOut() throws Exception {
		List<Long> ids = new ArrayList<>();
		for (long id = 1; id <= 15; id++) {
			rule(id, "Rule " + id, "Message", null, false);
			ids.add(id);
		}
		when(calls.ask(anyString(), eq(AssistantFeature.CWE_SUGGEST), anyString(), anyString(), anyString(), any()))
				.thenReturn(Optional.of(answer(item(1, "CWE-79", "First batch answer.", "medium"))))
				.thenThrow(new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "used up"));

		var result = service.suggest("editor", ids);

		assertEquals("BUDGET", result.get("stopped"));
		assertEquals(1, ((List<?>) result.get("suggestions")).size());
		assertEquals(14, skipped(result).get("unanswered"), "9 unanswered in the first batch plus 5 never asked");
		verify(calls, times(2)).ask(anyString(), eq(AssistantFeature.CWE_SUGGEST), anyString(), anyString(), anyString(), any());
	}

	@Test
	void requiresRuleModifyAndStaysQuietWhenTheFeatureIsOff() throws Exception {
		doThrow(new AccessDeniedException("no")).when(access).require("viewer", "Rule Modify");
		assertThrows(AccessDeniedException.class, () -> service.suggest("viewer", List.of(1L)));

		when(calls.readiness(AssistantFeature.CWE_SUGGEST))
				.thenReturn(new StructuredFeatureCall.Readiness("OFF", "CWE suggestions is off."));
		var off = service.suggest("editor", List.of(1L));
		assertEquals("OFF", off.get("state"));
		verify(calls, never()).ask(anyString(), any(), anyString(), anyString(), anyString(), any());
	}

	@Test
	void refusesAnEmptyOversizedOrInvalidSelection() {
		assertThrows(IllegalArgumentException.class, () -> service.suggest("editor", List.of()));
		assertThrows(IllegalArgumentException.class, () -> service.suggest("editor", null));
		assertThrows(IllegalArgumentException.class, () -> service.suggest("editor", List.of(0L)));
		List<Long> tooMany = new ArrayList<>();
		for (long id = 1; id <= RuleService.MAX_BULK_STEWARDSHIP + 1; id++) {
			tooMany.add(id);
		}
		assertThrows(IllegalArgumentException.class, () -> service.suggest("editor", tooMany));
	}
}
