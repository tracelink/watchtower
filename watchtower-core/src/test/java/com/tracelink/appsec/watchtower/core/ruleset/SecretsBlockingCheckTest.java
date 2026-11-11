package com.tracelink.appsec.watchtower.core.ruleset;

import java.util.Set;
import java.util.function.Predicate;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import com.tracelink.appsec.watchtower.core.mock.MockCustomRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class SecretsBlockingCheckTest {

	/** MockCustomRuleDto reports module "Mock"; treat it as a secrets module. */
	private static final Predicate<String> MOCK_IS_SENSITIVE = "Mock"::equals;

	private static RulesetDto rulesetWithMockRule(RulePriority blockingLevel) {
		MockCustomRuleDto rule = new MockCustomRuleDto();
		rule.setName("secret rule");
		rule.setPriority(RulePriority.MEDIUM);
		RulesetDto ruleset = new RulesetDto();
		ruleset.setName("pilot");
		ruleset.setBlockingLevel(blockingLevel);
		ruleset.setRules(Set.of(rule));
		return ruleset;
	}

	@ParameterizedTest
	@EnumSource(value = RulePriority.class, names = {"HIGH", "MEDIUM_HIGH"})
	public void testWarnsWhenMediumSecretsWouldNotBlock(RulePriority blockingLevel) {
		Assertions.assertTrue(SecretsBlockingCheck.shouldWarn(rulesetWithMockRule(blockingLevel),
				MOCK_IS_SENSITIVE));
	}

	@Test
	public void testWarnsWhenTheRulesetNeverBlocks() {
		Assertions.assertTrue(
				SecretsBlockingCheck.shouldWarn(rulesetWithMockRule(null), MOCK_IS_SENSITIVE));
	}

	@ParameterizedTest
	@EnumSource(value = RulePriority.class, names = {"MEDIUM", "MEDIUM_LOW", "LOW",
			"INFORMATIONAL"})
	public void testQuietWhenMediumSecretsBlock(RulePriority blockingLevel) {
		Assertions.assertFalse(SecretsBlockingCheck.shouldWarn(rulesetWithMockRule(blockingLevel),
				MOCK_IS_SENSITIVE));
	}

	@Test
	public void testQuietWithoutSecretsRules() {
		Assertions.assertFalse(SecretsBlockingCheck.shouldWarn(
				rulesetWithMockRule(RulePriority.HIGH), module -> false));
	}

	@Test
	public void testCountsInheritedSecretsRules() {
		RulesetDto primary = new RulesetDto();
		primary.setName("primary");
		primary.setBlockingLevel(RulePriority.HIGH);
		primary.setRulesets(Set.of(rulesetWithMockRule(RulePriority.MEDIUM)));

		Assertions.assertTrue(SecretsBlockingCheck.shouldWarn(primary, MOCK_IS_SENSITIVE));
	}

	@Test
	public void testNoRulesetMeansNoWarning() {
		Assertions.assertFalse(SecretsBlockingCheck.shouldWarn(null, MOCK_IS_SENSITIVE));
	}
}
