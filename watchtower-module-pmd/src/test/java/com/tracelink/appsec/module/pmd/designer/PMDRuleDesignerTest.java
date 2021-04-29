package com.tracelink.appsec.module.pmd.designer;

import java.util.Map;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class PMDRuleDesignerTest {
	private PMDRuleDesigner pmdDesigner;
	private final String defaultQuery =
			"//PrimaryPrefix[Name[starts-with(@Image,\"System.err\")]]";

	private final String defaultLanguage = "Java";

	private final String defaultSrc =
			"public class HelloWorld { public static void main(String[] args) { System.err.println(\"Hello, World\"); }}";

	@BeforeEach
	public void setup() {
		pmdDesigner = new PMDRuleDesigner();
	}

	@Test
	public void testGetRuleDesignerModelAndView() {
		RuleDesignerModelAndView mav = pmdDesigner.getRuleDesignerModelAndView();
		assertMav(mav);
	}

	@Test
	public void testQuery() {
		RuleDesignerModelAndView mav = pmdDesigner.query(defaultLanguage, defaultQuery, defaultSrc);
		assertMav(mav);
		MatcherAssert.assertThat(mav.getModel().get("language"), Matchers.is(defaultLanguage));
		MatcherAssert.assertThat(mav.getModel().get("query"), Matchers.is(defaultQuery));
		MatcherAssert.assertThat(mav.getModel().get("sourceCode"), Matchers.is(defaultSrc));
		MatcherAssert.assertThat(mav.getModel().get("matches"), Matchers.notNullValue());
		MatcherAssert.assertThat(mav.getModel().get("ast"), Matchers.notNullValue());
	}

	@Test
	public void testQueryUnknownLanguage() {
		RuleDesignerModelAndView mav = pmdDesigner.query("TEST", defaultQuery, defaultSrc);
		assertMav(mav);
		MatcherAssert.assertThat(mav.getModel().get(WatchtowerModelAndView.FAILURE_NOTIFICATION),
				Matchers.is("Unsupported Language"));
	}

	@Test
	public void testQueryBlankQuery() {
		RuleDesignerModelAndView mav = pmdDesigner.query(defaultLanguage, "", defaultSrc);
		assertMav(mav);
		MatcherAssert.assertThat(mav.getModel().get("language"), Matchers.is(defaultLanguage));
		MatcherAssert.assertThat(mav.getModel().get("query"), Matchers.is(""));
		MatcherAssert.assertThat(mav.getModel().get("sourceCode"), Matchers.is(defaultSrc));
		MatcherAssert.assertThat(mav.getModel().get("matches"), Matchers.notNullValue());
		MatcherAssert.assertThat(mav.getModel().get("ast"), Matchers.notNullValue());
	}


	private void assertMav(RuleDesignerModelAndView mav) {
		Map<String, Object> model = mav.getModel();
		MatcherAssert.assertThat(model.get("supportedLanguages"), Matchers.notNullValue());
		MatcherAssert.assertThat(model.get("help"), Matchers.notNullValue());
		MatcherAssert.assertThat(model.get("rulePriorities"), Matchers.is(RulePriority.values()));
		MatcherAssert.assertThat(model.get("scripts"), Matchers.notNullValue());
		MatcherAssert.assertThat(model.get("designerView"), Matchers.is("designer/pmd"));
	}

}
