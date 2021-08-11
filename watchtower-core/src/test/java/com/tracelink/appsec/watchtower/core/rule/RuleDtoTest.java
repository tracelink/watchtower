package com.tracelink.appsec.watchtower.core.rule;

import java.util.Collections;
import java.util.Set;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.mock.MockCustomRuleDto;

public class RuleDtoTest {

	@Test
	public void testSettersAndGetters() {
		long id = 3L;
		String author = "jdoe";
		String name = "MockRule";
		String message = "This is a bad practice";
		String url = "https://example.com/MockRule";
		Set<String> rulesets = Collections.singleton("Mock Ruleset");
		RulePriority priority = RulePriority.MEDIUM;
		CustomRuleDto dto = new MockCustomRuleDto();
		dto.setId(id);
		dto.setAuthor(author);
		dto.setName(name);
		dto.setMessage(message);
		dto.setExternalUrl(url);
		dto.setPriority(priority);
		dto.setRulesets(rulesets);

		Assertions.assertEquals("Mock", dto.getModule());
		Assertions.assertEquals(new Long(id), dto.getId());
		Assertions.assertEquals(author, dto.getAuthor());
		Assertions.assertEquals(name, dto.getName());
		Assertions.assertEquals(message, dto.getMessage());
		Assertions.assertEquals(url, dto.getExternalUrl());
		Assertions.assertEquals(priority, dto.getPriority());
		Assertions.assertEquals(rulesets, dto.getRulesets());
	}

	@Test
	public void testCompareToPriority() {
		RuleDto r1 = new MockCustomRuleDto();
		RuleDto r2 = new MockCustomRuleDto();
		r1.setPriority(RulePriority.LOW);
		r1.setName("Foo");
		r2.setPriority(RulePriority.MEDIUM);
		r2.setName("Bar");
		Assertions.assertTrue(r1.compareTo(r2) > 0);
	}

	@Test
	public void testCompareToName() {
		RuleDto r1 = new MockCustomRuleDto();
		RuleDto r2 = new MockCustomRuleDto();
		r1.setPriority(RulePriority.MEDIUM);
		r1.setName("Foo");
		r2.setPriority(RulePriority.MEDIUM);
		r2.setName("Bar");
		Assertions.assertTrue(r1.compareTo(r2) > 0);
	}

	@Test
	public void testGetRulesetsIsEmptySet() {
		RuleDto dto = new MockCustomRuleDto();
		Assertions.assertTrue(dto.getRulesets().isEmpty());
	}
}
