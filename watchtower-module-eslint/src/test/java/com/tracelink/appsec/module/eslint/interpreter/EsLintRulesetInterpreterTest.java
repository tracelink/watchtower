package com.tracelink.appsec.module.eslint.interpreter;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Collections;
import java.util.stream.Collectors;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import com.tracelink.appsec.module.eslint.model.EsLintCustomRuleDto;
import com.tracelink.appsec.module.eslint.model.EsLintRuleDtoTest;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetException;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.test.logging.LogWatchExtension;

public class EsLintRulesetInterpreterTest {

	@RegisterExtension
	public LogWatchExtension loggerRule =
			LogWatchExtension.forClass(EsLintRulesetExporter.class);

	private EsLintRulesetExporter interpreter;

	@BeforeEach
	public void setup() {
		interpreter = new EsLintRulesetExporter();
	}

	@Test
	public void testExportRuleset() throws Exception {
		String rulesetName = "ESLint Rules";
		String rulesetDesc = "A Description";
		RulesetDto rulesetDto = new RulesetDto();
		rulesetDto.setName(rulesetName);
		rulesetDto.setDescription(rulesetDesc);

		EsLintCustomRuleDto rule = EsLintRuleDtoTest.getCustomEsLintRule();
		rulesetDto.setRules(Collections.singleton(rule));
		try (BufferedReader br = new BufferedReader(
				new InputStreamReader(interpreter.exportRuleset(rulesetDto)))) {
			String exported = br.lines().collect(Collectors.joining("\n"));
			Assertions.assertTrue(exported.contains("name: \"" + rulesetName + "\""));
			Assertions.assertTrue(exported.contains(
					"description: \"" + rulesetDesc + "\""));
			MatcherAssert.assertThat(exported, Matchers.containsString(
					"\"" + rule.getName() + "\": " + rule.getPriority().getPriority() + ""));
		}
	}

	@Test
	public void testExportRulesetNoEsLintRules() throws Exception {
		Assertions.assertNull(interpreter.exportRuleset(new RulesetDto()));
	}

	@Test
	public void testExportRulesetMustacheException() throws Exception {
		RulesetDto rulesetDto = new RulesetDto();
		EsLintCustomRuleDto ruleDto = new EsLintCustomRuleDto();
		ruleDto.setName("foo");
		ruleDto.setPriority(RulePriority.LOW);
		rulesetDto.setRules(Collections.singleton(ruleDto));
		try {
			interpreter.exportRuleset(rulesetDto);
			Assertions.fail("Should have thrown exception");
		} catch (RulesetException e) {
			Assertions.assertEquals(
					"Error converting ruleset to template. Please check the log for more details.",
					e.getMessage());
			Assertions.assertFalse(loggerRule.getMessages().isEmpty());
			Assertions
					.assertTrue(loggerRule.getMessages().get(0).contains("Cannot export ruleset"));
		}
	}

}
