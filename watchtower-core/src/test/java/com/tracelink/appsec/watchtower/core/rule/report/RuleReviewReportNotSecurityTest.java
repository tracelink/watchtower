package com.tracelink.appsec.watchtower.core.rule.report;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleState;

/** A rule marked "not a security rule" has no CWE by design, so the report does not ask for one. */
class RuleReviewReportNotSecurityTest {
	private static final LocalDate TODAY = LocalDate.of(2026, 10, 12);

	private static RuleReviewReport.RuleFacts rule(long id, String cwe, boolean notSecurity) {
		return new RuleReviewReport.RuleFacts(id, "rule-" + id, "pmd", RulePriority.MEDIUM, RuleState.ACTIVE, "team", null, cwe,
				Set.of("java"), Map.of(), Map.of(), 0, null, notSecurity);
	}

	private static List<String> reasonsOf(List<Map<String, Object>> attention, long ruleId) {
		return attention.stream().filter(item -> ((Long) item.get("rule_id")) == ruleId).findFirst()
				.map(item -> ((List<?>) item.get("reasons")).stream().map(r -> (String) ((Map<?, ?>) r).get("code")).toList())
				.orElse(List.of());
	}

	@Test
	void aRuleWithoutACweIsFlaggedUnlessItIsMarkedNotASecurityRule() {
		var attention = RuleReviewReport.attention(List.of(rule(1, null, false), rule(2, null, true)), TODAY);

		assertTrue(reasonsOf(attention, 1).contains("NO_CWE"));
		assertFalse(reasonsOf(attention, 2).contains("NO_CWE"));
	}

	@Test
	void theOlderConstructorsStillMeanASecurityRule() {
		var old = new RuleReviewReport.RuleFacts(3, "rule-3", "pmd", RulePriority.MEDIUM, RuleState.ACTIVE, "team", null, null,
				Set.of("java"), Map.of(), Map.of(), 0);

		assertFalse(old.notSecurity());
		assertTrue(reasonsOf(RuleReviewReport.attention(List.of(old), TODAY), 3).contains("NO_CWE"));
	}

	@SuppressWarnings("unchecked")
	@Test
	void notASecurityRuleIsLeftOutOfTheCweMatrixAndTheUnclassifiedRow() {
		var report = RuleReviewReport.build(List.of(rule(1, "CWE-79", false), rule(2, null, true), rule(3, null, false)),
				RuleReviewReport.Catalog.load(), TODAY);

		List<Map<String, Object>> rows = (List<Map<String, Object>>) ((Map<String, Object>) report.get("matrix")).get("rows");
		Map<String, Object> unclassified = rows.stream().filter(row -> "Rules without a CWE".equals(row.get("name"))).findFirst()
				.orElseThrow();
		Map<String, Map<String, Object>> cells = (Map<String, Map<String, Object>>) unclassified.get("cells");
		assertEquals(1L, ((Number) cells.get("java").get("rules")).longValue(),
				"only the one rule that should have a CWE and does not is counted");
	}
}
