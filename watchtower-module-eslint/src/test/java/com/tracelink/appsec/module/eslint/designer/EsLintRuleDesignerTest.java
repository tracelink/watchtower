package com.tracelink.appsec.module.eslint.designer;

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
import com.tracelink.appsec.module.eslint.model.EsLintMessageDto;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class EsLintRuleDesignerTest {

	private static final String DEFAULT_SOURCE_CODE = "if (foo == null) {\n"
			+ "  bar();\n"
			+ "}\n"
			+ "\n"
			+ "while (qux != null) {\n"
			+ "  baz();\n"
			+ "}";

	private static final boolean DEFAULT_CORE = false;

	private static final String DEFAULT_NAME = "no-eq-null";

	private static final String DEFAULT_CREATE_FUNCTION = "create(context) {\n"
			+ "    return {\n"
			+ "        BinaryExpression(node) {\n"
			+ "            const badOperator = node.operator === \"==\" || node.operator === \"!=\";\n"
			+ "\n"
			+ "            if (node.right.type === \"Literal\" && node.right.raw === \"null\" && badOperator ||\n"
			+ "                    node.left.type === \"Literal\" && node.left.raw === \"null\" && badOperator) {\n"
			+ "                context.report({ node, messageId: \"unexpected\" });\n"
			+ "            }\n"
			+ "        }\n"
			+ "    };\n"
			+ "}";

	private static final List<EsLintMessageDto> DEFAULT_MESSAGES = Collections
			.singletonList(new EsLintMessageDto("unexpected", "Use '===' to compare with null."));

	private static final String INVALID_SOURCE_CODE = "var foo = \"Hello World!\";\n"
			+ "console.log(foo)\";;\n"
			+ "var a = eval(\"2 + 2\");";

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
		RuleDesignerModelAndView mav = ruleDesigner.getRuleDesignerModelAndView();
		assertMav(mav);
		MatcherAssert.assertThat(mav.getModel().get("sourceCode"),
				Matchers.is(DEFAULT_SOURCE_CODE));
		MatcherAssert.assertThat(mav.getModel().get("core"), Matchers.is(DEFAULT_CORE));
		MatcherAssert.assertThat(mav.getModel().get("name"), Matchers.is(DEFAULT_NAME));
		MatcherAssert.assertThat(mav.getModel().get("createFunction"),
				Matchers.is(DEFAULT_CREATE_FUNCTION));
		List<EsLintMessageDto> messages = (List<EsLintMessageDto>) mav.getModel().get("messages");
		MatcherAssert.assertThat(messages, Matchers.iterableWithSize(1));
		Assertions.assertEquals(DEFAULT_MESSAGES.get(0).getKey(), messages.get(0).getKey());
		Assertions.assertEquals(DEFAULT_MESSAGES.get(0).getValue(), messages.get(0).getValue());
		MatcherAssert.assertThat(mav.getModel().get("matches"), Matchers.notNullValue());
		MatcherAssert.assertThat(mav.getModel().get("ast"), Matchers.notNullValue());
	}

	@Test
	public void testQuery() {
		RuleDesignerModelAndView mav =
				ruleDesigner.query(DEFAULT_SOURCE_CODE, DEFAULT_CREATE_FUNCTION, DEFAULT_MESSAGES);
		assertMav(mav);
		MatcherAssert.assertThat(mav.getModel().get("sourceCode"),
				Matchers.is(DEFAULT_SOURCE_CODE));
		MatcherAssert.assertThat(mav.getModel().get("core"), Matchers.is(DEFAULT_CORE));
		MatcherAssert.assertThat(mav.getModel().get("name"), Matchers.is(DEFAULT_NAME));
		MatcherAssert.assertThat(mav.getModel().get("createFunction"),
				Matchers.is(DEFAULT_CREATE_FUNCTION));
		List<EsLintMessageDto> messages = (List<EsLintMessageDto>) mav.getModel().get("messages");
		MatcherAssert.assertThat(messages, Matchers.iterableWithSize(1));
		Assertions.assertEquals(DEFAULT_MESSAGES.get(0).getKey(), messages.get(0).getKey());
		Assertions.assertEquals(DEFAULT_MESSAGES.get(0).getValue(), messages.get(0).getValue());
		MatcherAssert.assertThat(mav.getModel().get("matches"), Matchers.notNullValue());
		MatcherAssert.assertThat(mav.getModel().get("ast"), Matchers.notNullValue());
	}

	@Test
	public void testQueryBlankSourceCode() {
		RuleDesignerModelAndView mav =
				ruleDesigner.query(null, DEFAULT_CREATE_FUNCTION, DEFAULT_MESSAGES);
		assertMav(mav);
		MatcherAssert.assertThat(mav.getModel().get("sourceCode"),
				Matchers.is(DEFAULT_SOURCE_CODE));
		MatcherAssert.assertThat(mav.getModel().get("core"), Matchers.is(DEFAULT_CORE));
		MatcherAssert.assertThat(mav.getModel().get("name"), Matchers.is(DEFAULT_NAME));
		MatcherAssert.assertThat(mav.getModel().get("createFunction"),
				Matchers.is(DEFAULT_CREATE_FUNCTION));
		List<EsLintMessageDto> messages = (List<EsLintMessageDto>) mav.getModel().get("messages");
		MatcherAssert.assertThat(messages, Matchers.iterableWithSize(1));
		Assertions.assertEquals(DEFAULT_MESSAGES.get(0).getKey(), messages.get(0).getKey());
		Assertions.assertEquals(DEFAULT_MESSAGES.get(0).getValue(), messages.get(0).getValue());
		MatcherAssert.assertThat(mav.getModel().get("matches"), Matchers.nullValue());
		MatcherAssert.assertThat(mav.getModel().get("ast"), Matchers.nullValue());
		MatcherAssert.assertThat(mav.getModel().get("failure"),
				Matchers.is("Please provide source code to test against the rule."));
	}

	@Test
	public void testQueryCoreBlankName() {
		RuleDesignerModelAndView mav = ruleDesigner.query(DEFAULT_SOURCE_CODE, null, null);
		assertMav(mav);
		MatcherAssert.assertThat(mav.getModel().get("sourceCode"),
				Matchers.is(DEFAULT_SOURCE_CODE));
		MatcherAssert.assertThat(mav.getModel().get("core"), Matchers.is(true));
		MatcherAssert.assertThat(mav.getModel().get("name"), Matchers.is(DEFAULT_NAME));
		MatcherAssert.assertThat(mav.getModel().get("createFunction"),
				Matchers.is(DEFAULT_CREATE_FUNCTION));
		List<EsLintMessageDto> messages = (List<EsLintMessageDto>) mav.getModel().get("messages");
		MatcherAssert.assertThat(messages, Matchers.iterableWithSize(1));
		Assertions.assertEquals(DEFAULT_MESSAGES.get(0).getKey(), messages.get(0).getKey());
		Assertions.assertEquals(DEFAULT_MESSAGES.get(0).getValue(), messages.get(0).getValue());
		MatcherAssert.assertThat(mav.getModel().get("matches"), Matchers.nullValue());
		MatcherAssert.assertThat(mav.getModel().get("ast"), Matchers.nullValue());
		MatcherAssert.assertThat(mav.getModel().get("failure"),
				Matchers.is("Must provide a rule name for a core rule."));
	}

	@Test
	public void testQueryCore() {
		RuleDesignerModelAndView mav = ruleDesigner.query(DEFAULT_SOURCE_CODE, null, null);
		assertMav(mav);
		MatcherAssert.assertThat(mav.getModel().get("sourceCode"),
				Matchers.is(DEFAULT_SOURCE_CODE));
		MatcherAssert.assertThat(mav.getModel().get("core"), Matchers.is(true));
		MatcherAssert.assertThat(mav.getModel().get("name"), Matchers.is(DEFAULT_NAME));
		MatcherAssert.assertThat(mav.getModel().get("createFunction"),
				Matchers.is(DEFAULT_CREATE_FUNCTION));
		List<EsLintMessageDto> messages = (List<EsLintMessageDto>) mav.getModel().get("messages");
		MatcherAssert.assertThat(messages, Matchers.iterableWithSize(1));
		Assertions.assertEquals(DEFAULT_MESSAGES.get(0).getKey(), messages.get(0).getKey());
		Assertions.assertEquals(DEFAULT_MESSAGES.get(0).getValue(), messages.get(0).getValue());
		MatcherAssert.assertThat((List<String>) mav.getModel().get("matches"),
				Matchers.containsInAnyOrder("Line 1: Use '===' to compare with null.",
						"Line 5: Use '===' to compare with null."));
		MatcherAssert.assertThat(mav.getModel().get("ast"), Matchers.notNullValue());
	}

	@Test
	public void testQueryCustomBlankCreateFunction() {
		RuleDesignerModelAndView mav = ruleDesigner.query(DEFAULT_SOURCE_CODE, null, null);
		assertMav(mav);
		MatcherAssert.assertThat(mav.getModel().get("sourceCode"),
				Matchers.is(DEFAULT_SOURCE_CODE));
		MatcherAssert.assertThat(mav.getModel().get("core"), Matchers.is(DEFAULT_CORE));
		MatcherAssert.assertThat(mav.getModel().get("name"), Matchers.is(DEFAULT_NAME));
		MatcherAssert.assertThat(mav.getModel().get("createFunction"),
				Matchers.is(DEFAULT_CREATE_FUNCTION));
		List<EsLintMessageDto> messages = (List<EsLintMessageDto>) mav.getModel().get("messages");
		MatcherAssert.assertThat(messages, Matchers.iterableWithSize(1));
		Assertions.assertEquals(DEFAULT_MESSAGES.get(0).getKey(), messages.get(0).getKey());
		Assertions.assertEquals(DEFAULT_MESSAGES.get(0).getValue(), messages.get(0).getValue());
		MatcherAssert.assertThat(mav.getModel().get("matches"), Matchers.nullValue());
		MatcherAssert.assertThat(mav.getModel().get("ast"), Matchers.nullValue());
		MatcherAssert.assertThat(mav.getModel().get("failure"),
				Matchers.is("Must provide create function for a custom rule."));
	}

	@Test
	public void testQueryCustomInvalidMessage() {
		RuleDesignerModelAndView mav =
				ruleDesigner.query(DEFAULT_SOURCE_CODE, DEFAULT_CREATE_FUNCTION,
						Collections.singletonList(new EsLintMessageDto("key", "")));
		assertMav(mav);
		MatcherAssert.assertThat(mav.getModel().get("sourceCode"),
				Matchers.is(DEFAULT_SOURCE_CODE));
		MatcherAssert.assertThat(mav.getModel().get("core"), Matchers.is(DEFAULT_CORE));
		MatcherAssert.assertThat(mav.getModel().get("name"), Matchers.is(DEFAULT_NAME));
		MatcherAssert.assertThat(mav.getModel().get("createFunction"),
				Matchers.is(DEFAULT_CREATE_FUNCTION));
		List<EsLintMessageDto> messages = (List<EsLintMessageDto>) mav.getModel().get("messages");
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
		RuleDesignerModelAndView mav = ruleDesigner.query(INVALID_SOURCE_CODE, null, null);
		assertMav(mav);
		MatcherAssert.assertThat(mav.getModel().get("sourceCode"),
				Matchers.is(INVALID_SOURCE_CODE));
		MatcherAssert.assertThat(mav.getModel().get("core"), Matchers.is(true));
		MatcherAssert.assertThat(mav.getModel().get("name"), Matchers.is("no-extra-semi"));
		MatcherAssert.assertThat(mav.getModel().get("createFunction"),
				Matchers.is(DEFAULT_CREATE_FUNCTION));
		List<EsLintMessageDto> messages = (List<EsLintMessageDto>) mav.getModel().get("messages");
		MatcherAssert.assertThat(messages, Matchers.iterableWithSize(1));
		Assertions.assertEquals(DEFAULT_MESSAGES.get(0).getKey(), messages.get(0).getKey());
		Assertions.assertEquals(DEFAULT_MESSAGES.get(0).getValue(), messages.get(0).getValue());
		MatcherAssert.assertThat(mav.getModel().get("matches"), Matchers.notNullValue());
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
