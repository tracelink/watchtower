package com.tracelink.appsec.watchtower.core.ruleset;

import java.util.Collections;
import java.util.Map;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.mock.MockCustomRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

public class RulesetDtoTest {

	private RulesetDto r1;
	private RulesetDto r2;

	@BeforeEach
	public void setup() {
		r1 = new RulesetDto();
		r2 = new RulesetDto();
	}

	@Test
	public void testCompareToSameName() {
		r1.setName("same");
		r1.setDesignation(RulesetDesignation.PRIMARY);
		r2.setName("same");
		r2.setDesignation(RulesetDesignation.PRIMARY);
		Assertions.assertEquals(0, r1.compareTo(r2));
	}

	@Test
	public void testCompareToOneDefault() {
		r1.setName("Default");
		r1.setDesignation(RulesetDesignation.DEFAULT);
		r2.setName("R2");
		r2.setDesignation(RulesetDesignation.PRIMARY);
		Assertions.assertTrue(r1.compareTo(r2) < 0);

		r1.setName("R1");
		r1.setDesignation(RulesetDesignation.SUPPORTING);
		r2.setName("Default");
		r2.setDesignation(RulesetDesignation.DEFAULT);
		Assertions.assertTrue(r1.compareTo(r2) > 0);
	}

	@Test
	public void testCompareToLexicographic() {
		r1.setName("Beta");
		r1.setDesignation(RulesetDesignation.SUPPORTING);
		r2.setName("Alpha");
		r2.setDesignation(RulesetDesignation.SUPPORTING);
		Assertions.assertTrue(r1.compareTo(r2) > 0);
	}

	@Test
	public void testGetRules() {
		RuleDto rule = new MockCustomRuleDto();
		rule.setName("Foo");
		rule.setPriority(RulePriority.MEDIUM);
		r1.setRules(Collections.singleton(rule));
		Assertions.assertEquals("Mock", r1.getRules().iterator().next().getModule());
	}

	@Test
	public void testGetRuleIds() {
		RuleDto rule = new MockCustomRuleDto();
		rule.setId(1L);
		r1.setRules(Collections.singleton(rule));
		Assertions.assertEquals(new Long(1L), r1.getRuleIds().iterator().next());
	}

	@Test
	public void testGetInheritedRules() {
		r1.setName("PMD Ruleset");
		r2.setName("Regex Ruleset");
		RulesetDto r3 = new RulesetDto();
		r3.setName("Default Ruleset");
		RuleDto pmdRule = new MockCustomRuleDto();
		pmdRule.setName("Foo");
		pmdRule.setPriority(RulePriority.MEDIUM);
		RuleDto regexRule = new MockCustomRuleDto();
		regexRule.setName("Bar");
		regexRule.setPriority(RulePriority.MEDIUM);

		r3.setRules(Collections.singleton(pmdRule));
		r2.setRules(Collections.singleton(regexRule));
		r1.setRulesets(Collections.singleton(r2));
		r2.setRulesets(Collections.singleton(r3));
		r3.setRulesets(Collections.emptySet());
		Map<RuleDto, String> inheritedRules = r1.getInheritedRules();
		Assertions.assertEquals(2, inheritedRules.size());
		Assertions.assertEquals(r2.getName(), inheritedRules.get(regexRule));
		Assertions.assertEquals(r3.getName(), inheritedRules.get(pmdRule));
	}

	@Test
	public void testGetNumRules() {
		r1.setName("PMD Ruleset");
		r2.setName("Regex Ruleset");
		RulesetDto r3 = new RulesetDto();
		r3.setName("Default Ruleset");
		RuleDto pmdRule = new MockCustomRuleDto();
		pmdRule.setName("Foo");
		pmdRule.setPriority(RulePriority.MEDIUM);
		RuleDto regexRule = new MockCustomRuleDto();
		regexRule.setName("Bar");
		regexRule.setPriority(RulePriority.MEDIUM);

		r1.setRules(Collections.emptySet());
		r2.setRules(Collections.singleton(regexRule));
		r3.setRules(Collections.singleton(pmdRule));
		r1.setRulesets(Collections.singleton(r2));
		r2.setRulesets(Collections.singleton(r3));
		r3.setRulesets(Collections.emptySet());
		Assertions.assertEquals(2, r1.getNumRules());
	}
}
