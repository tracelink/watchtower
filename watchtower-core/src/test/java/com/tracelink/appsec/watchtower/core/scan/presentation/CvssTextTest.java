package com.tracelink.appsec.watchtower.core.scan.presentation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class CvssTextTest {

	@Test
	void scoreReadsAsChipTextWithItsBand() {
		CvssText medium = CvssText.of("5.0", null);
		assertTrue(medium.scored());
		assertEquals("CVSS 5.0", medium.shortLabel());
		assertEquals("CVSS 5.0 · Medium", medium.label());
		assertEquals("3", medium.severityKey());

		assertEquals("CRITICAL", CvssText.of("9.8", null).severityKey());
		assertEquals("CVSS 9.8 · Critical", CvssText.of("9.8", null).label());
		assertEquals("1", CvssText.of("7.5", null).severityKey());
		assertEquals("5", CvssText.of("2.1", null).severityKey());
		assertEquals("6", CvssText.of("0.0", null).severityKey());
	}

	@Test
	void missingOrNonNumericScoreSaysNoCvss() {
		for (String score : new String[] {null, "", "N/A", "unknown"}) {
			CvssText text = CvssText.of(score, null);
			assertFalse(text.scored());
			assertEquals("No CVSS", text.shortLabel());
			assertEquals("No CVSS", text.label());
			assertEquals("UNKNOWN", text.severityKey());
			assertEquals("The advisory has no CVSS score", text.scoreTip());
		}
	}

	@Test
	void version2VectorReadsInPlainWords() {
		CvssText text = CvssText.of("5.0", "AV:N/AC:L/Au:N/C:N/I:N/A:P");
		assertEquals("Network · No auth · Availability", text.vectorText());
		assertTrue(text.vectorTip().startsWith("Vector AV:N/AC:L/Au:N/C:N/I:N/A:P:"));
		assertTrue(text.vectorTip().contains("reachable over the network"));
		assertTrue(text.vectorTip().contains("no login needed"));
		assertTrue(text.vectorTip().endsWith("Click to copy."));
	}

	@Test
	void version3VectorReadsInPlainWords() {
		CvssText text = CvssText.of("9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
		assertEquals("Network · No auth · Confidentiality, Integrity, Availability", text.vectorText());
		assertEquals("Local · Login needed · Confidentiality",
				CvssText.of("5.5", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N").vectorText());
	}

	@Test
	void unreadableOrMissingVectorKeepsTheRawCode() {
		assertNull(CvssText.of("5.0", null).vectorText());
		assertEquals("SOMETHING-ELSE", CvssText.of("5.0", "SOMETHING-ELSE").vectorText());
	}
}
