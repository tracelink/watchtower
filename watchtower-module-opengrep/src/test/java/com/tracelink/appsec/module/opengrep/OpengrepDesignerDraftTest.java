package com.tracelink.appsec.module.opengrep;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;

import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDraftData;

/** A drafted Opengrep rule fills the designer form; it is checked to be one JSON object. */
public class OpengrepDesignerDraftTest {
	private static final String RULE = "{\"languages\":[\"python\"],\"pattern\":\"cursor.execute($X + ...)\"}";
	private final OpengrepDesigner designer = new OpengrepDesigner();

	private static RuleDraftData draft(String definition) {
		return new RuleDraftData("id", "opengrep", "python", "No string-built SQL (Python)", "Use query parameters.", 2, "CWE-89", null,
				definition, null, "cursor.execute(\"select \" + user)", "cursor.execute(\"select ?\", (user,))",
				"Concatenating input into SQL lets it change the query.", "Coverage gap: CWE-89 · Python");
	}

	@Test
	@SuppressWarnings("unchecked")
	public void theDraftFillsTheFormFields() {
		RuleDesignerModelAndView mav = designer.getPrefilledRuleDesignerModelAndView(draft(RULE));

		Map<String, String> rule = (Map<String, String>) mav.getModel().get("draftRule");
		assertThat(rule).containsEntry("name", "No string-built SQL (Python)").containsEntry("priority", "MEDIUM_HIGH")
				.containsEntry("engineRuleId", "wt-no-string-built-sql-python").containsEntry("message", "Use query parameters.")
				.containsEntry("externalUrl", "https://cwe.mitre.org/data/definitions/89.html").containsEntry("definition", RULE);
		assertThat(rule).doesNotContainKeys("license", "source");
	}

	@Test
	public void aDraftWithoutACweHasNoReferenceUrl() {
		var noCwe = new RuleDraftData("id", "opengrep", null, "x", "m", 3, null, null, RULE, null, null, null, null, null);

		@SuppressWarnings("unchecked")
		Map<String, String> rule = (Map<String, String>) designer.getPrefilledRuleDesignerModelAndView(noCwe).getModel().get("draftRule");
		assertThat(rule).containsEntry("externalUrl", "");
	}

	@Test
	public void theRuleIdIsAStableSlugOfTheName() {
		assertThat(OpengrepDesigner.ruleId("  Hello, World!! ")).isEqualTo("wt-hello-world");
		assertThat(OpengrepDesigner.ruleId("!!!")).isEqualTo("wt-drafted-rule");
		assertThat(OpengrepDesigner.ruleId("x".repeat(200))).hasSize(3 + 80);
	}

	@Test
	public void onlyOneJsonObjectIsAnAcceptableDefinition() {
		assertThat(designer.validateDraft(draft(RULE))).isNull();
		assertThat(designer.validateDraft(draft("[1,2]"))).isEqualTo("An Opengrep rule definition must be one JSON object.");
		assertThat(designer.validateDraft(draft("rules:\n  - id: x"))).isEqualTo("An Opengrep rule definition must be valid JSON.");
	}
}
