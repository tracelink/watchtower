package com.tracelink.appsec.watchtower.core.rest.metrics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleService;

import net.minidev.json.JSONObject;

class RuleScannerLabelsTest {

	@Test
	void namesEachRuleAndItsScannerWithoutChangingTheCachedResult() {
		RuleService rules = mock(RuleService.class);
		RuleEntity pmdRule = mock(RuleEntity.class);
		RuleDto pmdDto = mock(RuleDto.class);
		when(pmdRule.getName()).thenReturn("CommentRequired");
		when(pmdRule.toDto()).thenReturn(pmdDto);
		when(pmdDto.getModule()).thenReturn("PMD");
		when(rules.getRulesByNames(any())).thenReturn(List.of(pmdRule));
		JSONObject cached = new JSONObject(Map.of(
				"labels", List.of("CommentRequired", "Betterleaks: private-key", "Gone rule"),
				"counts", List.of(65, 5, 2)));

		JSONObject labelled = RuleScannerLabels.label(cached, rules);

		assertEquals(List.of("CommentRequired", "private-key", "Gone rule"), labelled.get("names"));
		List<?> scanners = (List<?>) labelled.get("scanners");
		assertEquals(Map.of("name", "PMD", "icon", "coffee"), scanners.get(0));
		assertEquals(Map.of("name", "Betterleaks", "icon", "key"), scanners.get(1));
		assertNull(scanners.get(2), "a rule that no longer exists has no scanner, not a guessed one");
		assertFalse(cached.containsKey("names"), "the cached metrics object is not modified");
		assertEquals(cached.get("counts"), labelled.get("counts"));
	}

	@Test
	void keepsAPrefixThatIsNotAScannerName() {
		RuleService rules = mock(RuleService.class);
		when(rules.getRulesByNames(any())).thenReturn(List.of());
		JSONObject cached = new JSONObject(Map.of("labels", List.of("Note: odd name"), "counts", List.of(1)));

		JSONObject labelled = RuleScannerLabels.label(cached, rules);

		assertEquals(List.of("Note: odd name"), labelled.get("names"));
	}
}
