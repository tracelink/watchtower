package com.tracelink.appsec.module.betterleaks.verify;

import java.util.Set;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.betterleaks.BetterleaksModule;

public class VerifiableRulesTest {

	private static final Set<String> VALIDATING = Set.of("github-pat", "aws-access-token",
			"gitlab-pat");

	@Test
	public void testOnlyConfiguredRulesAreVerifiable() {
		VerifiableRules rules = new VerifiableRules(" github-pat , aws-access-token ", VALIDATING);

		Assertions.assertTrue(rules.isVerifiable("github-pat"));
		Assertions.assertTrue(rules.isVerifiable("aws-access-token"));
		Assertions.assertFalse(rules.isVerifiable("gitlab-pat"));
		Assertions.assertFalse(rules.isVerifiable(null));
	}

	@Test
	public void testAStarAllowsEveryRuleWithAProviderCheck() {
		Assertions.assertEquals(VALIDATING, new VerifiableRules("*", VALIDATING).ruleIds());
	}

	@Test
	public void testNothingConfiguredMeansNothingIsVerifiable() {
		Assertions.assertEquals(Set.of(), new VerifiableRules("  ", VALIDATING).ruleIds());
	}

	@Test
	public void testARuleWithoutAProviderCheckFailsStartupLoudly() {
		// A typo or a rule without `validate` would otherwise just never show a button.
		IllegalStateException e = Assertions.assertThrows(IllegalStateException.class,
				() -> new VerifiableRules("github-pat,generic-api-key", VALIDATING));
		MatcherAssert.assertThat(e.getMessage(), Matchers.containsString("generic-api-key"));
	}

	@Test
	public void testCustomRulesCanNeverBeVerified() {
		Assertions.assertThrows(IllegalStateException.class,
				() -> new VerifiableRules("custom-internal-token",
						Set.of("custom-internal-token")));
	}

	@Test
	public void testThePinnedListMatchesTheModuleVersionAndHoldsTheDefaults() {
		Set<String> pinned = VerifiableRules.validatingRules();

		Assertions.assertEquals(186, pinned.size());
		VerifiableRules defaults = new VerifiableRules(VerifiableRules.DEFAULT_RULES, pinned);
		Assertions.assertTrue(defaults.isVerifiable("github-pat"));
		Assertions.assertTrue(defaults.isVerifiable("aws-access-token"));
		Assertions.assertEquals(BetterleaksModule.BETTERLEAKS_VERSION,
				VerifiableRules.validatingRulesVersion());
	}
}
