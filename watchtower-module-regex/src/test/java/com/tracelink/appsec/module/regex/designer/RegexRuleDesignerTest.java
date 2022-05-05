package com.tracelink.appsec.module.regex.designer;

import java.util.Map;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class RegexRuleDesignerTest {
	private RegexRuleDesigner regexDesigner = new RegexRuleDesigner();

	private String defaultQuery = "test";
	private String defaultSrc = "test String";


	@Test
	public void testGetRuleDesignerModelAndView() {
		RuleDesignerModelAndView mav = regexDesigner.getDefaultRuleDesignerModelAndView();
		assertMav(mav);
	}

	@Test
	public void testQuery() {
		RuleDesignerModelAndView mav =
				regexDesigner.query(defaultQuery, defaultSrc);
		assertMav(mav);
		MatcherAssert.assertThat(mav.getModel().get("query"), Matchers.is(defaultQuery));
		MatcherAssert.assertThat(mav.getModel().get("sourceCode"), Matchers.is(defaultSrc));
		MatcherAssert.assertThat(mav.getModel().get("matches"), Matchers.notNullValue());
	}

	@Test
	public void testQueryBlankQuery() {
		RuleDesignerModelAndView mav = regexDesigner.query("", defaultSrc);
		assertMav(mav);
		MatcherAssert.assertThat(mav.getModel().get("query"), Matchers.is(""));
		MatcherAssert.assertThat(mav.getModel().get("sourceCode"), Matchers.is(defaultSrc));
		MatcherAssert.assertThat(mav.getModel().get("matches"), Matchers.notNullValue());
	}


	private void assertMav(RuleDesignerModelAndView mav) {
		Map<String, Object> model = mav.getModel();
		MatcherAssert.assertThat(model.get("help"), Matchers.notNullValue());
		MatcherAssert.assertThat(model.get("rulePriorities"), Matchers.is(RulePriority.values()));
		MatcherAssert.assertThat(model.get("scripts"), Matchers.notNullValue());
		MatcherAssert.assertThat(model.get("designerView"), Matchers.is("designer/regex"));
	}
}
