package com.tracelink.appsec.watchtower.core.ruleset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetChoices.Option;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetPageService.RulesetSummary;

class RulesetChoicesTest {

	private static RulesetSummary summary(long id, String name, RulesetDesignation designation) {
		return new RulesetSummary(id, name, null, designation, RulePriority.MEDIUM);
	}

	@Test
	void groupsTheDefaultYourRulesetsAndEachScannersRulesets() {
		RulesetChoices choices = RulesetChoices.of(List.of(
				summary(1, "Default Dev Ruleset", RulesetDesignation.DEFAULT),
				summary(2, "dnp app dev", RulesetDesignation.PRIMARY),
				summary(3, "Auto-Test Ruleset", RulesetDesignation.PRIMARY),
				summary(4, "Shared bits", RulesetDesignation.SUPPORTING),
				summary(5, "PMD - Quickstart", RulesetDesignation.PROVIDED),
				summary(6, "PMD - Best practices", RulesetDesignation.PROVIDED),
				summary(7, "Betterleaks - Secrets", RulesetDesignation.PROVIDED)));

		assertEquals(new Option(1, "Default Dev Ruleset", "Default Dev Ruleset"), choices.defaultRuleset());
		// The default is also one of your rulesets; supporting rulesets are only included by others.
		assertEquals(List.of("Auto-Test Ruleset", "Default Dev Ruleset", "dnp app dev"),
				choices.own().stream().map(Option::label).toList());
		assertEquals(List.of("Betterleaks", "PMD"),
				choices.scanners().stream().map(group -> group.scanner().name()).toList());
		// Under the scanner's tile a provided ruleset drops its "Module - " prefix, but it is
		// still found by searching for the scanner.
		RulesetChoices.ScannerGroup pmd = choices.scanners().get(1);
		assertEquals("coffee", pmd.scanner().icon());
		assertEquals(List.of("Best practices", "Quickstart"), pmd.rulesets().stream().map(Option::label).toList());
		assertEquals("PMD Quickstart", pmd.rulesets().get(1).search());
		assertEquals("2 rulesets", pmd.countLabel());
		assertEquals("1 ruleset", choices.scanners().get(0).countLabel());
		assertEquals(3, choices.scannerRulesetCount());
		assertEquals("PMD · Quickstart", choices.labelOf(5L));
		assertEquals("dnp app dev", choices.labelOf(2L));
		assertNull(choices.labelOf(4L));
		assertNull(choices.labelOf(null));
	}

	@Test
	void noDefaultAndNoRulesetsAreFine() {
		RulesetChoices choices = RulesetChoices.of(List.of(summary(2, "Only", RulesetDesignation.PRIMARY)));
		assertNull(choices.defaultRuleset());
		assertEquals(1, choices.own().size());
		assertTrue(choices.scanners().isEmpty());
		assertTrue(RulesetChoices.EMPTY.own().isEmpty());
		assertEquals(0, RulesetChoices.EMPTY.scannerRulesetCount());
	}
}
