package com.tracelink.appsec.module.betterleaks.service;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.BDDMockito;

import com.tracelink.appsec.module.betterleaks.engine.BetterleaksRuleTestResult;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDtoTest;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksProvidedRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleException;

public class BetterleaksCustomRuleImportValidatorTest {

	private BetterleaksRuleTester tester;

	private BetterleaksCustomRuleImportValidator validator;

	@BeforeEach
	public void setup() {
		tester = BDDMockito.mock(BetterleaksRuleTester.class);
		validator = new BetterleaksCustomRuleImportValidator(tester);
	}

	@Test
	public void testSupportsOnlyCustomBetterleaksRules() {
		Assertions.assertTrue(validator.supports(BetterleaksCustomRuleDtoTest.validRule()));
		Assertions.assertFalse(validator.supports(new BetterleaksProvidedRuleDto()));
		Assertions.assertFalse(validator.supports(BDDMockito.mock(RuleDto.class)));
	}

	@Test
	public void testAcceptsARuleThatPassesItsSampleTest() throws Exception {
		BetterleaksCustomRuleDto rule = BetterleaksCustomRuleDtoTest.validRule();
		BDDMockito.when(tester.test(rule)).thenReturn(new BetterleaksRuleTestResult(true, false,
				null));

		validator.validate(rule);
	}

	@Test
	public void testRejectsAnImportedRuleThatFailsItsSampleTest() {
		BetterleaksCustomRuleDto rule = BetterleaksCustomRuleDtoTest.validRule();
		BDDMockito.when(tester.test(rule)).thenReturn(new BetterleaksRuleTestResult(false, false,
				null));

		RuleException e = Assertions.assertThrows(RuleException.class,
				() -> validator.validate(rule));

		MatcherAssert.assertThat(e.getMessage(), Matchers.containsString("positive sample"));
	}

	@Test
	public void testRejectsAnImportedRuleWithUnsafeFieldsBeforeRunningAnything() {
		BetterleaksCustomRuleDto rule = BetterleaksCustomRuleDtoTest.validRule();
		rule.setFilter("http.get(\"https://example.invalid\")");

		Assertions.assertThrows(RuleException.class, () -> validator.validate(rule));
		BDDMockito.verifyNoInteractions(tester);
	}
}
