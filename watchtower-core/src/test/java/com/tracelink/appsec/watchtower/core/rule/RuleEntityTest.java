package com.tracelink.appsec.watchtower.core.rule;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.mock.MockRuleEntity;

public class RuleEntityTest {
	@Test
	public void testDecodeFieldError() {
		Assertions.assertEquals("",
				new RuleEntity.HexStringConverter().convertToEntityAttribute("zyxwvut"));
	}

	@Test
	public void testGetRulesetsIsEmptySet() {
		RuleEntity rule = new MockRuleEntity();
		Assertions.assertTrue(rule.getRulesets().isEmpty());
	}
}
