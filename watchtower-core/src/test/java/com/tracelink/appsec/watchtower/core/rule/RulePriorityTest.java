package com.tracelink.appsec.watchtower.core.rule;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class RulePriorityTest {
	@Test
	public void testGetPriority() {
		for (RulePriority rulePriority : RulePriority.values()) {
			Assertions.assertEquals(rulePriority.ordinal() + 1, rulePriority.getPriority());
		}
	}

	@Test
	public void testGetName() {
		Assertions.assertEquals("Medium High", RulePriority.MEDIUM_HIGH.getName());
	}

	@Test
	public void testValueOf() {
		Assertions.assertEquals(RulePriority.MEDIUM_LOW, RulePriority.valueOf(4));
	}

	@Test
	public void testValueOfInvalid() {
		Assertions.assertEquals(RulePriority.LOW, RulePriority.valueOf(0));
		Assertions.assertEquals(RulePriority.LOW, RulePriority.valueOf(6));
	}
}
