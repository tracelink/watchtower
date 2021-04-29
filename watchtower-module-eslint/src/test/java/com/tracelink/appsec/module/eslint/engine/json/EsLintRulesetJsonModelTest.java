package com.tracelink.appsec.module.eslint.engine.json;

import java.util.Collections;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class EsLintRulesetJsonModelTest {

	@Test
	public void testGettersAndSetters() {
		EsLintRulesetJsonModel rulesetJsonModel = new EsLintRulesetJsonModel();
		rulesetJsonModel.setName("ESLint Ruleset");
		rulesetJsonModel.setDescription("Some rules");
		rulesetJsonModel.setCustomRules(Collections.emptyMap());
		rulesetJsonModel.setPriorities(Collections.emptyMap());

		Assertions.assertEquals("ESLint Ruleset", rulesetJsonModel.getName());
		Assertions.assertEquals("Some rules", rulesetJsonModel.getDescription());
		Assertions.assertTrue(rulesetJsonModel.getCustomRules().isEmpty());
		Assertions.assertTrue(rulesetJsonModel.getPriorities().isEmpty());
	}
}
