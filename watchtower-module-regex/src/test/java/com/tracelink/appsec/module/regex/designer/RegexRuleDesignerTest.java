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
		// Each match is a line the "Line N" chip can jump to.
		MatcherAssert.assertThat((java.util.List<?>) regexDesigner.query("accessKeys",
				"Watchtower Regex\nCan help us find accessKeys\nOr other data.").getModel().get("matches"),
				Matchers.contains(com.tracelink.appsec.watchtower.core.module.designer.DesignerMatch.atLine(2,
						"Matched by the pattern")));
	}

	@Test
	public void testQueryThatNeverFinishesIsStoppedAndSaysSo() {
		// A backreference defeats the JDK's backtracking memoization, so without the match
		// timeout this call would not return.
		RuleDesignerModelAndView mav = regexDesigner.query("(a*)*\\1b", "a".repeat(40));

		MatcherAssert.assertThat((java.util.List<?>) mav.getModel().get("matches"),
				Matchers.contains(com.tracelink.appsec.watchtower.core.module.designer.DesignerMatch.note(
						"The pattern did not finish on this sample, so it was stopped. It may take too long to match.")));
	}

	@Test
	public void testPatternThatDoesNotCompileIsExplainedNotThrown() {
		// Dev E2E G02: an unclosed class answered with a bare HTTP 500.
		RuleDesignerModelAndView mav = regexDesigner.query("([unclosed", defaultSrc);

		assertMav(mav);
		MatcherAssert.assertThat(mav.getModel().get("query"), Matchers.is("([unclosed"));
		java.util.List<?> matches = (java.util.List<?>) mav.getModel().get("matches");
		MatcherAssert.assertThat(matches, Matchers.hasSize(1));
		MatcherAssert.assertThat(matches.get(0).toString(),
				Matchers.containsString("The regular expression does not compile"));
	}

	@Test
	public void testQueryBlankQuery() {
		RuleDesignerModelAndView mav = regexDesigner.query("", defaultSrc);
		assertMav(mav);
		MatcherAssert.assertThat(mav.getModel().get("query"), Matchers.is(""));
		MatcherAssert.assertThat(mav.getModel().get("sourceCode"), Matchers.is(defaultSrc));
		MatcherAssert.assertThat((java.util.List<?>) mav.getModel().get("matches"), Matchers.empty());
	}


	private void assertMav(RuleDesignerModelAndView mav) {
		Map<String, Object> model = mav.getModel();
		MatcherAssert.assertThat(model.get("help"), Matchers.notNullValue());
		MatcherAssert.assertThat(model.get("rulePriorities"), Matchers.is(RulePriority.values()));
		MatcherAssert.assertThat(model.get("scripts"), Matchers.notNullValue());
		MatcherAssert.assertThat(model.get("designerView"), Matchers.is("designer/regex"));
	}
}
