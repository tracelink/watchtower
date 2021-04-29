package com.tracelink.appsec.module.eslint.interpreter;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Collections;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import com.tracelink.appsec.module.eslint.model.EsLintRuleDto;
import com.tracelink.appsec.module.eslint.model.EsLintRuleFixable;
import com.tracelink.appsec.watchtower.core.module.interpreter.RulesetInterpreterException;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.test.logging.LogWatchExtension;

public class EsLintRulesetInterpreterTest {

	@RegisterExtension
	public LogWatchExtension loggerRule =
			LogWatchExtension.forClass(EsLintRulesetInterpreter.class);

	private final EsLintRulesetInterpreter interpreter = new EsLintRulesetInterpreter();

	@Test
	public void testImportRuleset() throws Exception {
		try (InputStream is = getClass().getClassLoader()
				.getResourceAsStream("import/ruleset.js")) {
			RulesetDto rulesetDto = interpreter.importRuleset(is);
			Assertions.assertEquals("ESLint Rules", rulesetDto.getName());
			Assertions.assertEquals("A collection of custom and core ESLint rules",
					rulesetDto.getDescription());
			Assertions.assertEquals(4, rulesetDto.getRules().size());
			Assertions.assertTrue(rulesetDto.getRules().stream().anyMatch(ruleDto -> {
				EsLintRuleDto esLintRuleDto = (EsLintRuleDto) ruleDto;
				return esLintRuleDto.isCore() && esLintRuleDto.getName().equals("no-console")
						&& esLintRuleDto.getPriority().equals(RulePriority.MEDIUM_LOW);
			}));
			Assertions.assertTrue(rulesetDto.getRules().stream().anyMatch(ruleDto -> {
				EsLintRuleDto esLintRuleDto = (EsLintRuleDto) ruleDto;
				return esLintRuleDto.isCore() && esLintRuleDto.getName().equals("no-eval")
						&& esLintRuleDto.getPriority().equals(RulePriority.MEDIUM_HIGH);
			}));
			Assertions.assertTrue(rulesetDto.getRules().stream().anyMatch(ruleDto -> {
				EsLintRuleDto esLintRuleDto = (EsLintRuleDto) ruleDto;
				return !esLintRuleDto.isCore() && esLintRuleDto.getName().equals("my-no-eq-null")
						&& esLintRuleDto.getPriority().equals(RulePriority.MEDIUM_LOW)
						&& esLintRuleDto.getMessage()
								.equals("disallow 'null' comparisons without type-checking operators")
						&& !esLintRuleDto.getMessages().isEmpty() && esLintRuleDto.getMessages()
								.get(0).getValue().equals("Use '===' to compare with null.")
						&& esLintRuleDto.getExternalUrl()
								.equals("https://eslint.org/docs/rules/no-eq-null");
			}));
			Assertions.assertTrue(rulesetDto.getRules().stream().anyMatch(ruleDto -> {
				EsLintRuleDto esLintRuleDto = (EsLintRuleDto) ruleDto;
				return !esLintRuleDto.isCore() && esLintRuleDto.getName().equals("my-no-extra-semi")
						&& esLintRuleDto.getPriority().equals(RulePriority.LOW)
						&& esLintRuleDto.getMessage().equals("disallow unnecessary semicolons")
						&& !esLintRuleDto.getMessages().isEmpty() && esLintRuleDto.getMessages()
								.get(0).getValue().equals("Unnecessary semicolon.")
						&& esLintRuleDto.getExternalUrl().equals("https://www.example.com")
						&& esLintRuleDto.getReplacedBy() != null
						&& esLintRuleDto.getFixable().equals(EsLintRuleFixable.CODE)
						&& esLintRuleDto.getRecommended() && esLintRuleDto.getSuggestion()
						&& esLintRuleDto.getDeprecated();
			}));
		}
	}

	@Test
	public void testImportRulesetInvalidJavaScript() throws Exception {
		try (InputStream is = getClass().getClassLoader()
				.getResourceAsStream("import/invalid-js.js")) {
			interpreter.importRuleset(is);
			Assertions.fail("Should have thrown exception");
		} catch (RulesetInterpreterException e) {
			Assertions.assertEquals(
					"The ESLint ruleset cannot be parsed. Parsing error: Unterminated string constant",
					e.getMessage());
		}
	}

	@Test
	public void testImportRulesetNoRulesetObject() throws Exception {
		try (InputStream is = getClass().getClassLoader()
				.getResourceAsStream("import/no-ruleset-object.js")) {
			interpreter.importRuleset(is);
			Assertions.fail("Should have thrown exception");
		} catch (RulesetInterpreterException e) {
			Assertions.assertEquals(
					"The ESLint ruleset cannot be parsed. Please provide a Javascript file whose module.exports contains a single ruleset object",
					e.getMessage());
		}
	}

	@Test
	public void testImportRulesetNoPriorityForCustomRule() throws Exception {
		try (InputStream is = getClass().getClassLoader()
				.getResourceAsStream("import/custom-rule-no-priority.js")) {
			interpreter.importRuleset(is);
			Assertions.fail("Should have thrown exception");
		} catch (RulesetInterpreterException e) {
			Assertions.assertEquals(
					"No rule priority provided for the custom rule \"my-no-eq-null\".",
					e.getMessage());
		}
	}

	@Test
	public void testImportRulesetInvalidCoreRule() throws Exception {
		try (InputStream is = getClass().getClassLoader()
				.getResourceAsStream("import/invalid-core-rule.js")) {
			interpreter.importRuleset(is);
			Assertions.fail("Should have thrown exception");
		} catch (RulesetInterpreterException e) {
			Assertions.assertEquals("No rule definition provided for the custom rule \"foo\".",
					e.getMessage());
		}
	}

	@Test
	public void testImportRulesetInvalidRulesetObject() throws Exception {
		try (InputStream is = getClass().getClassLoader()
				.getResourceAsStream("import/invalid-ruleset-object.js")) {
			interpreter.importRuleset(is);
			Assertions.fail("Should have thrown exception");
		} catch (RulesetInterpreterException e) {
			Assertions.assertEquals(
					"The ESLint ruleset is incorrectly formatted. Please check the log for more details.",
					e.getMessage());
			Assertions.assertFalse(loggerRule.getMessages().isEmpty());
			String message = loggerRule.getMessages().get(0);
			Assertions.assertTrue(message.contains("Cannot translate ESLint ruleset to DTO"));
		}
	}

	@Test
	public void testExportRuleset() throws Exception {
		try (InputStream is = getClass().getClassLoader()
				.getResourceAsStream("import/ruleset.js")) {
			RulesetDto rulesetDto = interpreter.importRuleset(is);
			try (BufferedReader br = new BufferedReader(
					new InputStreamReader(interpreter.exportRuleset(rulesetDto)))) {
				String exported = br.lines().collect(Collectors.joining("\n"));
				Assertions.assertTrue(exported.contains("name: \"ESLint Rules\""));
				Assertions.assertTrue(exported.contains(
						"description: \"A collection of custom and core ESLint rules\""));
				Assertions.assertTrue(exported.contains("\"my-no-eq-null\": 4"));
				Assertions.assertTrue(exported.contains("\"my-no-extra-semi\": 5"));
				Assertions.assertTrue(exported.contains("\"no-console\": 4"));
				Assertions.assertTrue(exported.contains("\"no-eval\": 2"));
				Assertions.assertEquals(3, exported.split("meta:").length);
				Assertions.assertEquals(3, exported.split("create").length);
				Assertions.assertEquals(3, exported.split("my-no-extra-semi").length);
				Assertions.assertEquals(3, exported.split("my-no-eq-null").length);
				Assertions.assertEquals(2, exported.split("no-eval").length);
				Assertions.assertEquals(2, exported.split("no-console").length);
			}
		}
	}

	@Test
	public void testExportRulesetNoEsLintRules() throws Exception {
		Assertions.assertNull(interpreter.exportRuleset(new RulesetDto()));
	}

	@Test
	public void testExportRulesetMustacheException() throws Exception {
		RulesetDto rulesetDto = new RulesetDto();
		EsLintRuleDto ruleDto = new EsLintRuleDto();
		ruleDto.setName("foo");
		ruleDto.setPriority(RulePriority.LOW);
		rulesetDto.setRules(Collections.singleton(ruleDto));
		try {
			interpreter.exportRuleset(rulesetDto);
			Assertions.fail("Should have thrown exception");
		} catch (RulesetInterpreterException e) {
			Assertions.assertEquals(
					"Error converting ruleset to template. Please check the log for more details.",
					e.getMessage());
			Assertions.assertFalse(loggerRule.getMessages().isEmpty());
			Assertions
					.assertTrue(loggerRule.getMessages().get(0).contains("Cannot export ruleset"));
		}
	}

	@Test
	public void testGetExtension() {
		Assertions.assertEquals("js", interpreter.getExtension());
	}
}
