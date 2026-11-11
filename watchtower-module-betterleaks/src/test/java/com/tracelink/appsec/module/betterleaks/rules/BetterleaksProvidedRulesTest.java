package com.tracelink.appsec.module.betterleaks.rules;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.betterleaks.BetterleaksModule;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksCategory;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksProvidedRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDesignation;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

public class BetterleaksProvidedRulesTest {

	private static final List<BetterleaksProvidedRuleDto> RULES =
			BetterleaksProvidedRules.load().rules();

	private static final Map<String, BetterleaksProvidedRuleDto> BY_ID = RULES.stream()
			.collect(Collectors.toMap(BetterleaksProvidedRuleDto::getBetterleaksId,
					Function.identity()));

	@Test
	public void testLoadsEveryReportableRuleOfThePinnedVersion() {
		BetterleaksProvidedRules provided = BetterleaksProvidedRules.load();

		Assertions.assertEquals(BetterleaksModule.BETTERLEAKS_VERSION, provided.version());
		Assertions.assertEquals(385, provided.rules().size());
		// Component-only rules never report on their own, so they are not Watchtower rules.
		Assertions.assertFalse(BY_ID.containsKey("aws-secret-access-key"));
	}

	@Test
	public void testRuleCarriesItsIdentityGuidanceAndCategoryPriority() {
		BetterleaksProvidedRuleDto rule = BY_ID.get("github-pat");

		Assertions.assertEquals("Betterleaks: github-pat", rule.getName());
		MatcherAssert.assertThat(rule.getMessage(),
				Matchers.startsWith("Uncovered a GitHub Personal Access Token"));
		Assertions.assertEquals(BetterleaksProvidedRules.EXTERNAL_URL, rule.getExternalUrl());
		Assertions.assertEquals(BetterleaksCategory.SCM, rule.getCategory());
		Assertions.assertEquals(RulePriority.HIGH, rule.getPriority());
		Assertions.assertEquals("high", rule.getConfidence());
		Assertions.assertEquals(BetterleaksModule.MODULE_NAME, rule.getModule());
		Assertions.assertTrue(rule.isProvided());
	}

	@Test
	public void testGenericRulesDefaultToMedium() {
		Assertions.assertEquals(RulePriority.MEDIUM, BY_ID.get("generic-api-key").getPriority());
	}

	@Test
	public void testEveryRuleNameFitsTheCoreRuleNameLimit() {
		RULES.forEach(rule -> MatcherAssert.assertThat(rule.getName(),
				Matchers.hasLength(Matchers.lessThanOrEqualTo(100))));
	}

	@Test
	public void testDefaultRulesetHoldsEveryRuleAndBlocksAtMedium() {
		RulesetDto ruleset = BetterleaksProvidedRules.load().toDefaultRuleset();

		Assertions.assertEquals(BetterleaksProvidedRules.DEFAULT_RULESET_NAME, ruleset.getName());
		Assertions.assertEquals(RulesetDesignation.PROVIDED, ruleset.getDesignation());
		// Generic secrets are MEDIUM, so a lower threshold would silently let them through.
		Assertions.assertEquals(RulePriority.MEDIUM, ruleset.getBlockingLevel());
		Assertions.assertEquals(385, ruleset.getRules().size());
	}

	@Test
	public void testEachLoadReturnsFreshRuleObjects() {
		// Rulesets and priorities are set on these objects during registration; a shared cached
		// instance would leak one caller's changes into the next.
		Assertions.assertNotSame(BetterleaksProvidedRules.load().rules().get(0),
				BetterleaksProvidedRules.load().rules().get(0));
	}
}
