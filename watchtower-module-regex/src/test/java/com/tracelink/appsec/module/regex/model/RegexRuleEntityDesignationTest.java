package com.tracelink.appsec.module.regex.model;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.rule.RuleDesignation;

public class RegexRuleEntityDesignationTest {

	@Test
	public void aProvidedRuleReportsProvided() {
		RegexRuleEntity rule = new RegexRuleEntity();
		rule.setProvided(true);

		Assertions.assertEquals(RuleDesignation.PROVIDED, rule.designationOfThisRule());
	}

	@Test
	public void aRuleThatIsNotProvidedReportsCustomEvenWhenProvidedRulesExist() {
		RegexRuleEntity provided = new RegexRuleEntity();
		provided.setProvided(true);
		RegexRuleEntity custom = new RegexRuleEntity();

		Assertions.assertEquals(RuleDesignation.CUSTOM, custom.designationOfThisRule());
		Assertions.assertEquals(RuleDesignation.PROVIDED, provided.designationOfThisRule());
	}
}
