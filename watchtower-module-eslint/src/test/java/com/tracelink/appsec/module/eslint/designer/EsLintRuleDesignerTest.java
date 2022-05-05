package com.tracelink.appsec.module.eslint.designer;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.eslint.engine.LinterEngine;
import com.tracelink.appsec.module.eslint.model.EsLintCustomRuleDto;
import com.tracelink.appsec.module.eslint.model.EsLintMessageDto;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class EsLintRuleDesignerTest {

	private static final String INVALID_SOURCE_CODE = "var foo = \"Hello World!\";\n"
			+ "console.log(foo)\";;\n"
			+ "var a = eval(\"2 + 2\");";
	private static final List<EsLintMessageDto> DEFAULT_MESSAGES = Collections
			.singletonList(new EsLintMessageDto(EsLintRuleDesigner.DEFAULT_MESSAGE_KEY,
					EsLintRuleDesigner.DEFAULT_MESSAGE_VALUE));

	private EsLintRuleDesigner ruleDesigner;

	private static LinterEngine engine;

	@BeforeAll
	public static void init() {
		engine = new LinterEngine();
	}

	@BeforeEach
	public void setup() {
		ruleDesigner = new EsLintRuleDesigner(engine);
	}

	@Test
	public void testGetRuleDesignerModelAndView() {
		RuleDesignerModelAndView mav = ruleDesigner.getDefaultRuleDesignerModelAndView();
		assertMav(mav);
		MatcherAssert.assertThat(mav.getModel().get("sourceCode"),
				Matchers.is(EsLintRuleDesigner.DEFAULT_SOURCE_CODE));
		EsLintCustomRuleDto rule = (EsLintCustomRuleDto) mav.getModel().get("rule");
		MatcherAssert.assertThat(rule.getName(), Matchers.is(EsLintRuleDesigner.DEFAULT_NAME));
		MatcherAssert.assertThat(rule.getCreateFunction(),
				Matchers.is(EsLintRuleDesigner.DEFAULT_CREATE_FUNCTION));
		List<EsLintMessageDto> messages = rule.getMessages();
		MatcherAssert.assertThat(messages, Matchers.iterableWithSize(1));
		Assertions.assertEquals(DEFAULT_MESSAGES.get(0).getKey(), messages.get(0).getKey());
		Assertions.assertEquals(DEFAULT_MESSAGES.get(0).getValue(), messages.get(0).getValue());
		MatcherAssert.assertThat(mav.getModel().get("matches"), Matchers.notNullValue());
		MatcherAssert.assertThat(mav.getModel().get("ast"), Matchers.notNullValue());
	}

	@Test
	public void testQuery() {
		RuleDesignerModelAndView mav =
				ruleDesigner.query(EsLintRuleDesigner.DEFAULT_SOURCE_CODE,
						EsLintRuleDesigner.DEFAULT_CREATE_FUNCTION,
						DEFAULT_MESSAGES);
		assertMav(mav);
		MatcherAssert.assertThat(mav.getModel().get("sourceCode"),
				Matchers.is(EsLintRuleDesigner.DEFAULT_SOURCE_CODE));
		EsLintCustomRuleDto rule = (EsLintCustomRuleDto) mav.getModel().get("rule");
		MatcherAssert.assertThat(rule.getName(), Matchers.is(EsLintRuleDesigner.DEFAULT_NAME));
		MatcherAssert.assertThat(rule.getCreateFunction(),
				Matchers.is(EsLintRuleDesigner.DEFAULT_CREATE_FUNCTION));
		List<EsLintMessageDto> messages = rule.getMessages();
		MatcherAssert.assertThat(messages, Matchers.iterableWithSize(1));
		Assertions.assertEquals(DEFAULT_MESSAGES.get(0).getKey(), messages.get(0).getKey());
		Assertions.assertEquals(DEFAULT_MESSAGES.get(0).getValue(), messages.get(0).getValue());
		MatcherAssert.assertThat(mav.getModel().get("matches"), Matchers.notNullValue());
		MatcherAssert.assertThat(mav.getModel().get("ast"), Matchers.notNullValue());
	}

	@Test
	public void testQueryBlankSourceCode() {
		RuleDesignerModelAndView mav =
				ruleDesigner.query(null, EsLintRuleDesigner.DEFAULT_CREATE_FUNCTION,
						DEFAULT_MESSAGES);
		assertMav(mav);
		MatcherAssert.assertThat(mav.getModel().get("failure"),
				Matchers.is("Please provide source code to test against the rule."));
	}

	@Test
	public void testQueryCustomBlankCreateFunction() {
		RuleDesignerModelAndView mav =
				ruleDesigner.query(EsLintRuleDesigner.DEFAULT_SOURCE_CODE, null, null);
		assertMav(mav);
		EsLintCustomRuleDto rule = (EsLintCustomRuleDto) mav.getModel().get("rule");
		MatcherAssert.assertThat(rule.getName(), Matchers.is(EsLintRuleDesigner.DEFAULT_NAME));
		List<EsLintMessageDto> messages = rule.getMessages();
		MatcherAssert.assertThat(messages, Matchers.iterableWithSize(0));
		MatcherAssert.assertThat(mav.getModel().get("failure"),
				Matchers.is("Must provide create function for a custom rule."));
	}

	@Test
	public void testQueryCustomInvalidMessage() {
		RuleDesignerModelAndView mav =
				ruleDesigner.query(EsLintRuleDesigner.DEFAULT_SOURCE_CODE,
						EsLintRuleDesigner.DEFAULT_CREATE_FUNCTION,
						Collections.singletonList(new EsLintMessageDto("key", "")));
		assertMav(mav);
		EsLintCustomRuleDto rule = (EsLintCustomRuleDto) mav.getModel().get("rule");
		MatcherAssert.assertThat(rule.getName(), Matchers.is(EsLintRuleDesigner.DEFAULT_NAME));
		MatcherAssert.assertThat(rule.getCreateFunction(),
				Matchers.is(EsLintRuleDesigner.DEFAULT_CREATE_FUNCTION));
		List<EsLintMessageDto> messages = rule.getMessages();
		MatcherAssert.assertThat(messages, Matchers.iterableWithSize(1));
		Assertions.assertEquals("key", messages.get(0).getKey());
		Assertions.assertEquals("", messages.get(0).getValue());
		MatcherAssert.assertThat(mav.getModel().get("matches"), Matchers.nullValue());
		MatcherAssert.assertThat(mav.getModel().get("ast"), Matchers.nullValue());
		MatcherAssert.assertThat(mav.getModel().get("failure"),
				Matchers.is("Messages for a custom rule must have a valid ID and value."));
	}

	@Test
	public void testQueryInvalidSourceCode() {
		RuleDesignerModelAndView mav = ruleDesigner.query(INVALID_SOURCE_CODE,
				EsLintRuleDesigner.DEFAULT_CREATE_FUNCTION, null);
		assertMav(mav);
		MatcherAssert.assertThat(mav.getModel().get("sourceCode"),
				Matchers.is(INVALID_SOURCE_CODE));
		EsLintCustomRuleDto rule = (EsLintCustomRuleDto) mav.getModel().get("rule");
		MatcherAssert.assertThat(rule.getName(), Matchers.is(EsLintRuleDesigner.DEFAULT_NAME));
		MatcherAssert.assertThat((Collection<?>) mav.getModel().get("matches"), Matchers.empty());
		MatcherAssert.assertThat(mav.getModel().get("ast"), Matchers.nullValue());
		MatcherAssert.assertThat((String) mav.getModel().get("failure"),
				Matchers.containsString("Parsing error: Unterminated string constant"));
	}

	private void assertMav(RuleDesignerModelAndView mav) {
		Map<String, Object> model = mav.getModel();
		MatcherAssert.assertThat(model.get("help"), Matchers.notNullValue());
		MatcherAssert.assertThat(model.get("rulePriorities"), Matchers.is(RulePriority.values()));
		MatcherAssert.assertThat(model.get("scripts"), Matchers.notNullValue());
		MatcherAssert.assertThat(model.get("designerView"), Matchers.is("designer/eslint"));
	}
}
