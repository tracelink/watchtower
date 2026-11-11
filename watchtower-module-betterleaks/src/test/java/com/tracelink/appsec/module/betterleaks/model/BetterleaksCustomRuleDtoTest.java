package com.tracelink.appsec.module.betterleaks.model;

import java.util.List;
import java.util.function.Consumer;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.betterleaks.BetterleaksModule;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class BetterleaksCustomRuleDtoTest {

	/** A valid custom rule; each test breaks one field. Samples are synthetic. */
	public static BetterleaksCustomRuleDto validRule() {
		BetterleaksCustomRuleDto rule = new BetterleaksCustomRuleDto();
		rule.setBetterleaksId("custom-example-internal-token");
		rule.setName("Betterleaks: custom-example-internal-token");
		rule.setMessage("An example internal service token.");
		rule.setExternalUrl("https://wiki.example.invalid/secrets");
		rule.setAuthor("alice");
		rule.setPriority(RulePriority.HIGH);
		rule.setRegex("tlk_int_[A-Za-z0-9]{16}");
		rule.setKeywords(List.of("tlk_int_"));
		rule.setEntropy(3.0);
		rule.setSecretGroup(null);
		rule.setFilter(null);
		rule.setPositiveSample("token = tlk_int_Q7m2Zp9Xc4Vb8Nn1");
		rule.setNegativeSample("token = tlk_int_short");
		return rule;
	}

	private static List<String> problemsAfter(Consumer<BetterleaksCustomRuleDto> change) {
		BetterleaksCustomRuleDto rule = validRule();
		change.accept(rule);
		return rule.fieldProblems();
	}

	@Test
	public void testValidRuleHasNoProblems() {
		Assertions.assertEquals(List.of(), validRule().fieldProblems());
		Assertions.assertEquals(BetterleaksModule.MODULE_NAME, validRule().getModule());
		Assertions.assertEquals(BetterleaksCategory.CUSTOM, validRule().getCategory());
	}

	@Test
	public void testIdMustBeACustomSlugSoItCannotShadowAProvidedRule() {
		Assertions.assertFalse(problemsAfter(r -> r.setBetterleaksId("github-pat")).isEmpty());
		Assertions.assertFalse(problemsAfter(r -> r.setBetterleaksId("custom-")).isEmpty());
		Assertions.assertFalse(problemsAfter(r -> r.setBetterleaksId("custom-Bad Id")).isEmpty());
		Assertions.assertFalse(problemsAfter(r -> r.setBetterleaksId(null)).isEmpty());
	}

	@Test
	public void testFieldsThatReachTheConfigCannotBreakOutOfTheirTomlString() {
		Assertions.assertFalse(problemsAfter(r -> r.setRegex("a'''\n[[allowlists]]")).isEmpty());
		Assertions.assertFalse(problemsAfter(r -> r.setRegex("a\nb")).isEmpty());
		Assertions.assertFalse(problemsAfter(r -> r.setFilter("true'''")).isEmpty());
		Assertions.assertFalse(problemsAfter(r -> r.setKeywords(List.of("a'b"))).isEmpty());
		Assertions.assertFalse(problemsAfter(r -> r.setKeywords(List.of("a b"))).isEmpty());
	}

	@Test
	public void testFilterCannotMakeNetworkCalls() {
		// Custom rules only filter; live validation (network calls from Watchtower) is limited
		// to the vetted provided rules.
		MatcherAssert.assertThat(
				problemsAfter(r -> r.setFilter("http.get(\"https://example.invalid\").status == 200")),
				Matchers.hasItem(Matchers.containsString("network")));
		// CEL allows whitespace around the dot, so a substring check alone is not enough.
		MatcherAssert.assertThat(
				problemsAfter(r -> r.setFilter("HTTP \t.get(\"https://example.invalid\") == null")),
				Matchers.hasItem(Matchers.containsString("network")));
		MatcherAssert.assertThat(problemsAfter(r -> r.setFilter("finding[\"match\"] == \"http\"")),
				Matchers.not(Matchers.hasItem(Matchers.containsString("network"))));
	}

	@Test
	public void testRequiresRegexAndBothSamples() {
		Assertions.assertFalse(problemsAfter(r -> r.setRegex(" ")).isEmpty());
		Assertions.assertFalse(problemsAfter(r -> r.setPositiveSample("")).isEmpty());
		Assertions.assertFalse(problemsAfter(r -> r.setNegativeSample(null)).isEmpty());
	}

	@Test
	public void testBoundsNumericAndSizeFields() {
		Assertions.assertFalse(problemsAfter(r -> r.setEntropy(9.0)).isEmpty());
		Assertions.assertFalse(problemsAfter(r -> r.setEntropy(-1.0)).isEmpty());
		Assertions.assertFalse(problemsAfter(r -> r.setSecretGroup(21)).isEmpty());
		Assertions.assertFalse(problemsAfter(r -> r.setRegex("a".repeat(1001))).isEmpty());
		Assertions.assertFalse(problemsAfter(r -> r.setPositiveSample("a".repeat(10_001)))
				.isEmpty());
		Assertions.assertFalse(problemsAfter(r -> r.setKeywords(
				List.of("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"))).isEmpty());
	}

	@Test
	public void testDtoToEntityToDtoRoundTripsACustomRule() {
		BetterleaksCustomRuleDto original = validRule();
		original.setVersion(3);

		BetterleaksCustomRuleDto copy = (BetterleaksCustomRuleDto) original.toEntity().toDto();

		Assertions.assertEquals(original.getBetterleaksId(), copy.getBetterleaksId());
		Assertions.assertEquals(original.getRegex(), copy.getRegex());
		Assertions.assertEquals(original.getKeywords(), copy.getKeywords());
		Assertions.assertEquals(original.getEntropy(), copy.getEntropy());
		Assertions.assertEquals(original.getPositiveSample(), copy.getPositiveSample());
		Assertions.assertEquals(original.getNegativeSample(), copy.getNegativeSample());
		Assertions.assertEquals("alice", copy.getAuthor());
		Assertions.assertEquals(3, copy.getVersion());
		Assertions.assertTrue(copy.isCustom());
	}
}
