package com.tracelink.appsec.watchtower.core.ruleset;

import java.util.LinkedHashSet;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.mock.MockRuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class ProvidedRulesFingerprintTest {

	private static RuleDto rule(String name, String message) {
		MockRuleEntity rule = new MockRuleEntity(true);
		rule.setName(name);
		rule.setAuthor("system");
		rule.setMessage(message);
		rule.setExternalUrl("https://example.invalid/" + name);
		rule.setPriority(RulePriority.HIGH);
		return rule.toDto();
	}

	private static RulesetDto ruleset(RuleDto... rules) {
		RulesetDto ruleset = new RulesetDto();
		ruleset.setName("Module - Provided");
		ruleset.setDescription("Provided rules");
		ruleset.setDesignation(RulesetDesignation.PROVIDED);
		ruleset.setBlockingLevel(RulePriority.HIGH);
		ruleset.setRules(new LinkedHashSet<>(List.of(rules)));
		return ruleset;
	}

	private static String fingerprint(RulesetDto ruleset) {
		return ProvidedRulesFingerprint.of(List.of(ruleset));
	}

	@Test
	public void testSameRulesInAnotherOrderGiveTheSameFingerprint() {
		String first = fingerprint(ruleset(rule("a", "m1"), rule("b", "m2")));
		String second = fingerprint(ruleset(rule("b", "m2"), rule("a", "m1")));

		Assertions.assertEquals(first, second);
		Assertions.assertEquals(64, first.length());
	}

	@Test
	public void testAChangedRuleChangesTheFingerprint() {
		Assertions.assertNotEquals(fingerprint(ruleset(rule("a", "m1"))),
				fingerprint(ruleset(rule("a", "m1 reworded"))));
	}

	@Test
	public void testAChangedRulesetChangesTheFingerprint() {
		RulesetDto changed = ruleset(rule("a", "m1"));
		changed.setBlockingLevel(RulePriority.MEDIUM);

		Assertions.assertNotEquals(fingerprint(ruleset(rule("a", "m1"))), fingerprint(changed));
	}

	@Test
	public void testAnAddedRuleChangesTheFingerprint() {
		Assertions.assertNotEquals(fingerprint(ruleset(rule("a", "m1"))),
				fingerprint(ruleset(rule("a", "m1"), rule("b", "m2"))));
	}

	@Test
	public void testFieldBoundariesCannotCollide() {
		// "a|b" + "c" must differ from "a" + "b|c", and a null from the text "null".
		Assertions.assertNotEquals(fingerprint(ruleset(rule("a|b", "c"))),
				fingerprint(ruleset(rule("a", "b|c"))));
		Assertions.assertNotEquals(ProvidedRulesFingerprint.describe(rule("x", null)),
				ProvidedRulesFingerprint.describe(rule("x", "null")));
	}
}
