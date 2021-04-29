package com.tracelink.appsec.module.json.designer;

import java.util.Map;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class JsonRuleDesignerTest {
	private JsonRuleDesigner jsonDesigner = new JsonRuleDesigner();

	private String query = "$";
	private String code = "{}";

	@Test
	public void testGetRuleDesignerModelAndView() {
		RuleDesignerModelAndView mav = jsonDesigner.getRuleDesignerModelAndView();
		assertMav(mav);
	}

	@Test
	public void testQuery() {
		RuleDesignerModelAndView mav = jsonDesigner.query(query, code);
		assertMav(mav);
		MatcherAssert.assertThat(mav.getModel().get("query"), Matchers.is(query));
		MatcherAssert.assertThat(mav.getModel().get("code"), Matchers.is(code));
		MatcherAssert.assertThat(mav.getModel().get("matches"), Matchers.notNullValue());
	}

	@Test
	public void testQueryBlankQuery() {
		RuleDesignerModelAndView mav = jsonDesigner.query("", code);
		assertMav(mav);
		MatcherAssert.assertThat(mav.getModel().get("query"), Matchers.is(""));
		MatcherAssert.assertThat(mav.getModel().get("code"), Matchers.is(code));
		MatcherAssert.assertThat(mav.getModel().get("matches"), Matchers.notNullValue());
	}

	private void assertMav(RuleDesignerModelAndView mav) {
		Map<String, Object> model = mav.getModel();
		MatcherAssert.assertThat(model.get("help"), Matchers.notNullValue());
		MatcherAssert.assertThat(model.get("rulePriorities"), Matchers.is(RulePriority.values()));
		MatcherAssert.assertThat(model.get("scripts"), Matchers.notNullValue());
		MatcherAssert.assertThat(model.get("designerView"), Matchers.is("designer/json"));
	}
}
