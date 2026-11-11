package com.tracelink.appsec.watchtower.core.module.designer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

class DesignerMatchTest {

	@Test
	void countsOnlyResultsWithALineAsMatches() {
		List<DesignerMatch> results = List.of(DesignerMatch.atLine(1, "Matched"), DesignerMatch.atLine(5, ""),
				DesignerMatch.note("Could not parse the sample"));

		assertEquals(2, DesignerMatch.countMatches(results));
		assertEquals(0, DesignerMatch.countMatches(null));
		assertTrue(results.get(0).hasLine());
		assertFalse(results.get(2).hasLine());
	}

	@Test
	void linesStartAtOneAndMessagesAreNeverNull() {
		assertThrows(IllegalArgumentException.class, () -> DesignerMatch.atLine(0, "x"));
		assertEquals("", new DesignerMatch(3, null).message());
	}
}
