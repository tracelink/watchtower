package com.tracelink.appsec.watchtower.core.logging;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LogLineTest {

	@Test
	void splitsTheLogsServicePattern() {
		LogLine line = LogLine.parse(
				"2026-10-16 13:58:36.512 c.t.a.w.c.s.c.s.r.c.CatalogSyncHandler INFO  - Synced BitBucket\n");

		assertEquals("2026-10-16", line.date());
		assertEquals("13:58:36", line.time());
		assertEquals("INFO", line.level());
		assertEquals("info", line.levelKey());
		assertEquals("CatalogSyncHandler", line.shortLogger());
		assertEquals("c.t.a.w.c.s.c.s.r.c.CatalogSyncHandler", line.logger());
		assertEquals("Synced BitBucket", line.message());
	}

	@Test
	void keepsStackTraceLinesInTheMessage() {
		LogLine line = LogLine.parse("2026-10-16 07:13:29.001 Foo ERROR - Boom\n\tat a.b.C.d(C.java:1)\n");

		assertEquals("ERROR", line.level());
		assertEquals("Foo", line.shortLogger());
		assertEquals("Boom\n\tat a.b.C.d(C.java:1)", line.message());
	}

	@Test
	void unrecognisedLineKeepsItsText() {
		LogLine line = LogLine.parse("something else");

		assertEquals("", line.level());
		assertEquals("other", line.levelKey());
		assertEquals("something else", line.message());
		assertEquals("something else", line.text());
		assertEquals("", LogLine.parse(null).message());
	}
}
