package com.tracelink.appsec.module.checkov.interpreter;

import java.util.ArrayList;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.BDDMockito;

import com.tracelink.appsec.module.checkov.engine.CheckovEngine;
import com.tracelink.appsec.watchtower.core.module.interpreter.RulesetInterpreterException;

public class CheckovRulesetInterpreterTest {

	@Test
	public void testImportNonCoreRules() {
		CheckovEngine mockEngine = BDDMockito.mock(CheckovEngine.class);
		BDDMockito.when(mockEngine.getCoreRules()).thenReturn(new ArrayList<>());

		CheckovRulesetJsonModel ruleset = new CheckovRulesetJsonModel();
		CheckovCoreRuleModel coreRule = new CheckovCoreRuleModel();
		coreRule.setCoreRuleName("notCoreRule");
		ruleset.getRules().add(coreRule);

		CheckovRulesetInterpreter interpreter = new CheckovRulesetInterpreter(mockEngine);
		try {
			interpreter.importInternal(ruleset);
			Assertions.fail("Should throw exception");
		} catch (RulesetInterpreterException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.containsString("not Checkov Core Rules"));
		}

	}
}
