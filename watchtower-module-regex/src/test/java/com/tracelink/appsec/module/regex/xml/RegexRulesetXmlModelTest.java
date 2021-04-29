package com.tracelink.appsec.module.regex.xml;

import java.util.Collections;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class RegexRulesetXmlModelTest {

	@Test
	public void testGettersAndSetters() {
		RegexRulesetXmlModel regexRulesetXmlModel = new RegexRulesetXmlModel();
		regexRulesetXmlModel.setName("Ruleset-Name");
		regexRulesetXmlModel.setDescription("This is a mock ruleset.\n");
		RegexRuleXmlModel ruleXmlModel = new RegexRuleXmlModel();
		regexRulesetXmlModel.setRules(Collections.singleton(ruleXmlModel));
		Assertions.assertEquals("Ruleset-Name", regexRulesetXmlModel.getName());
		Assertions.assertEquals("This is a mock ruleset.", regexRulesetXmlModel.getDescription());
		Assertions.assertEquals(ruleXmlModel, regexRulesetXmlModel.getRules().iterator().next());
	}
}
