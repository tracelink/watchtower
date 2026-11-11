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
		RuleDesignerModelAndView mav = jsonDesigner.getDefaultRuleDesignerModelAndView();
		assertMav(mav);
	}

	@Test
	public void testQuery() {
		RuleDesignerModelAndView mav = jsonDesigner.query(query, code);
		assertMav(mav);
		MatcherAssert.assertThat(mav.getModel().get("query"), Matchers.is(query));
		MatcherAssert.assertThat(mav.getModel().get("code"), Matchers.is(code));
		MatcherAssert.assertThat(mav.getModel().get("matches"), Matchers.notNullValue());
		RuleDesignerModelAndView yaml = jsonDesigner.query("$..privileged", "privileged: true\n---\nprivileged: true\n", "yaml");
		// Each match carries its line (the chip jumps there) and which YAML document it is in.
		org.junit.jupiter.api.Assertions.assertEquals(java.util.List.of(
				com.tracelink.appsec.watchtower.core.module.designer.DesignerMatch.atLine(1, "YAML document 1"),
				com.tracelink.appsec.watchtower.core.module.designer.DesignerMatch.atLine(3, "YAML document 2")),
				yaml.getModel().get("matches"));
		org.junit.jupiter.api.Assertions.assertEquals("yaml", yaml.getModel().get("sourceFormat"));
		org.junit.jupiter.api.Assertions.assertTrue(((java.util.List<?>)jsonDesigner.query("$", "a: [", "yaml").getModel().get("matches")).getFirst().toString().contains("Could not parse"));
	}

	@Test
	public void testJsonPathThatDoesNotParseIsExplainedNotThrown() {
		// Dev E2E G02: "$.[[bad" answered with a bare HTTP 500.
		RuleDesignerModelAndView mav = jsonDesigner.query("$.[[bad", "{\"a\":1}");

		assertMav(mav);
		MatcherAssert.assertThat(mav.getModel().get("query"), Matchers.is("$.[[bad"));
		java.util.List<?> matches = (java.util.List<?>) mav.getModel().get("matches");
		MatcherAssert.assertThat(matches, Matchers.hasSize(1));
		MatcherAssert.assertThat(matches.get(0).toString(),
				Matchers.containsString("The JSONPath query is not valid"));
	}

	@Test
	public void testQueryBlankQuery() {
		RuleDesignerModelAndView mav = jsonDesigner.query("", code);
		assertMav(mav);
		MatcherAssert.assertThat(mav.getModel().get("query"), Matchers.is(""));
		MatcherAssert.assertThat(mav.getModel().get("code"), Matchers.is(code));
		// A blank query has run nothing: no matches, not one blank match.
		MatcherAssert.assertThat((java.util.List<?>) mav.getModel().get("matches"), Matchers.empty());
	}

	private void assertMav(RuleDesignerModelAndView mav) {
		Map<String, Object> model = mav.getModel();
		MatcherAssert.assertThat(model.get("help"), Matchers.notNullValue());
		MatcherAssert.assertThat(model.get("rulePriorities"), Matchers.is(RulePriority.values()));
		MatcherAssert.assertThat(model.get("scripts"), Matchers.notNullValue());
		MatcherAssert.assertThat(model.get("designerView"), Matchers.is("designer/json"));
	}
}
