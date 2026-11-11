package com.tracelink.appsec.module.json.designer;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDraftData;

/** A drafted JSONPath opens in the JSON designer already run on its example. */
public class JsonRuleDesignerDraftTest {
	private final JsonRuleDesigner designer = new JsonRuleDesigner();

	private static RuleDraftData draft(String language, String query, String example) {
		return new RuleDraftData("id", "json", language, "Debug mode on", "Turn debug off.", 3, "CWE-489", null, query, ".json", example,
				"{\"debug\": false}", "Debug mode leaks internals.", "Coverage gap: CWE-489");
	}

	@Test
	public void theDraftedQueryRunsOnTheDraftedExampleAndTheSaveFieldsAreFilled() {
		RuleDesignerModelAndView mav = designer.getPrefilledRuleDesignerModelAndView(draft("json", "$[?(@.debug == true)]", "{\"debug\": true}"));

		assertThat(mav.getModel()).containsEntry("query", "$[?(@.debug == true)]").containsEntry("sourceFormat", "json")
				.containsEntry("ruleName", "Debug mode on").containsEntry("ruleMessage", "Turn debug off.").containsEntry("rulePriority", 3)
				.containsEntry("ruleFileExt", ".json");
		assertThat((List<?>) mav.getModel().get("matches")).isNotEmpty();
		assertThat(mav.getModel().get("code")).isEqualTo("{\"debug\": true}");
	}

	@Test
	public void yamlIsKeptAndAnythingElseIsJson() {
		assertThat(designer.getPrefilledRuleDesignerModelAndView(draft("YAML", "$.debug", "debug: true\n")).getModel())
				.containsEntry("sourceFormat", "yaml");
		assertThat(designer.getPrefilledRuleDesignerModelAndView(draft(null, "$.debug", "{}")).getModel()).containsEntry("sourceFormat", "json");
	}

	@Test
	public void aQueryThatIsNotValidIsRefused() {
		assertThat(designer.validateDraft(draft("json", "$[?(", null))).isEqualTo("The JSONPath query is not valid.");
		assertThat(designer.validateDraft(draft("json", "$.debug", null))).isNull();
	}
}
