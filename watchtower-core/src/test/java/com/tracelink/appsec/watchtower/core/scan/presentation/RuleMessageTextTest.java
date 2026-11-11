package com.tracelink.appsec.watchtower.core.scan.presentation;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class RuleMessageTextTest {

	@Test
	void placeholdersReadThisMember() {
		assertEquals("Consider giving this member package visibility to access it from this class.",
				RuleMessageText.readable("Consider giving {0} package visibility to access it from this class."));
		assertEquals("This member is never used.", RuleMessageText.readable("''{0}'' is never used."));
	}

	@Test
	void plainMessagesAreUnchanged() {
		assertEquals("The user-supplied array is stored directly.",
				RuleMessageText.readable("The user-supplied array is stored directly."));
		assertEquals("", RuleMessageText.readable(null));
	}
}
