package com.tracelink.appsec.module.pmd.designer;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.module.designer.DesignerMatch;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDraftData;

/** A drafted XPath opens in the PMD designer already run on its example. */
public class PMDRuleDesignerDraftTest {
	private static final String CLASS = "public class A {\n    void m(String id) {\n        System.out.println(id);\n    }\n}";
	private static final String PRINTLN = "//MethodCall[@MethodName = \"println\"]";
	private final PMDRuleDesigner designer = new PMDRuleDesigner();

	private static RuleDraftData draft(String language, String xpath, String vulnerable) {
		return new RuleDraftData("id", "pmd", language, "No System.out", "Use the logger.", 4, "CWE-532", null, xpath, null,
				vulnerable, "class B {}", "Console output is not logged safely.", "Coverage gap: CWE-532");
	}

	@Test
	public void theDraftedXPathRunsOnTheDraftedExampleAndTheSaveFieldsAreFilled() {
		RuleDesignerModelAndView mav = designer.getPrefilledRuleDesignerModelAndView(draft("java", PRINTLN, CLASS));

		assertThat(mav.getModel()).containsEntry("query", PRINTLN).containsEntry("language", "Java").containsEntry("ruleName", "No System.out")
				.containsEntry("ruleMessage", "Use the logger.").containsEntry("ruleLanguage", "Java").containsEntry("rulePriority", 4);
		@SuppressWarnings("unchecked")
		List<DesignerMatch> matches = (List<DesignerMatch>) mav.getModel().get("matches");
		assertThat(matches).containsExactly(DesignerMatch.atLine(3, "Selected by the XPath query"));
	}

	@Test
	public void noLanguageMeansJava() {
		assertThat(designer.getPrefilledRuleDesignerModelAndView(draft(null, PRINTLN, CLASS)).getModel()).containsEntry("language", "Java");
	}

	@Test
	public void anXPathPmdCannotRunOrAnUnknownLanguageIsRefused() {
		assertThat(designer.validateDraft(draft("Java", "//[[", CLASS))).startsWith("PMD could not");
		assertThat(designer.validateDraft(draft("Cobol", PRINTLN, CLASS))).isEqualTo("PMD does not support Cobol.");
		assertThat(designer.validateDraft(draft("Java", PRINTLN, CLASS))).isNull();
		assertThat(designer.validateDraft(draft("Java", PRINTLN, null))).as("nothing to run it on yet").isNull();
	}
}
