package com.tracelink.appsec.watchtower.core.scan.code;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class CommitIdsTest {

	private static final String FULL = "f09e278142698caed756e05a20827844d43d786b";

	@Test
	void anAbbreviatedCommitMatchesTheFullOneOnlyWhenItIsItsPrefix() {
		assertTrue(CommitIds.same(FULL, "f09e27814269"));
		assertTrue(CommitIds.same("f09e27814269", FULL));
		assertTrue(CommitIds.same(FULL, FULL.toUpperCase()));
		assertFalse(CommitIds.same(FULL, "f09e27814260"));
		assertFalse(CommitIds.same(FULL, "f09e27"), "too short to name one commit");
		assertFalse(CommitIds.same(FULL, null));
		assertFalse(CommitIds.same(null, null));
	}
}
