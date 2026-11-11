package com.tracelink.appsec.module.regex.designer;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.module.designer.DesignerMatch;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDraftData;

/** A drafted regex opens in the designer already run on its example. */
public class RegexRuleDesignerDraftTest {
	private final RegexRuleDesigner designer = new RegexRuleDesigner();

	private static RuleDraftData draft(String pattern, String vulnerable) {
		return new RuleDraftData("id", "regex", null, "Hard-coded http URL", "Use https.", 3, "CWE-319", null, pattern, ".java",
				vulnerable, "String u = \"https://example.com\";", "Plain http is readable on the network.", "Coverage gap: CWE-319");
	}

	@Test
	public void theDraftedPatternRunsOnTheDraftedExampleAndTheSaveFieldsAreFilled() {
		RuleDesignerModelAndView mav = designer.getPrefilledRuleDesignerModelAndView(
				draft("\"http://", "String a = 1;\nString u = \"http://example.com\";"));

		assertThat(mav.getModel()).containsEntry("query", "\"http://").containsEntry("ruleName", "Hard-coded http URL")
				.containsEntry("ruleMessage", "Use https.").containsEntry("rulePriority", 3).containsEntry("ruleFileExt", ".java");
		assertThat(mav.getModel().get("sourceCode")).isEqualTo("String a = 1;\nString u = \"http://example.com\";");
		@SuppressWarnings("unchecked")
		List<DesignerMatch> matches = (List<DesignerMatch>) mav.getModel().get("matches");
		assertThat(matches).containsExactly(DesignerMatch.atLine(2, "Matched by the pattern"));
	}

	@Test
	public void aDraftWithoutAnExampleOpensWithAnEmptySample() {
		RuleDesignerModelAndView mav = designer.getPrefilledRuleDesignerModelAndView(draft("abc", null));

		assertThat(mav.getModel().get("sourceCode")).isEqualTo("");
		assertThat((List<?>) mav.getModel().get("matches")).isEmpty();
	}

	@Test
	public void aPatternThatDoesNotCompileIsRefusedWithAReason() {
		assertThat(designer.validateDraft(draft("(", null))).startsWith("The regular expression does not compile");
		assertThat(designer.validateDraft(draft("\"http://", null))).isNull();
	}
}
