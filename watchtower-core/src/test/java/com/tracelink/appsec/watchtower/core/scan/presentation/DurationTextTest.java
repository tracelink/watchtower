package com.tracelink.appsec.watchtower.core.scan.presentation;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class DurationTextTest {

	@Test
	public void testSubSecondAndSecondsKeepTheirUnits() {
		assertEquals("850 ms", DurationText.of(850));
		assertEquals("8.00 s", DurationText.of(8_000));
	}

	@Test
	public void testMinutesReadAsMinutesAndSeconds() {
		assertEquals("10m 12s", DurationText.of(612_000));
		assertEquals("10m 11s", DurationText.of(611_999));
		assertEquals("1m 0s", DurationText.of(60_000));
	}

	@Test
	public void testNoDurationIsNotRecorded() {
		assertEquals("Not recorded", DurationText.of(-1));
	}

	@Test
	public void testHomeListsAndReportsAgree() {
		long start = 1_000_000L;
		assertEquals(DurationText.minutesAndSeconds(609_600),
				HomeActivityItem.formatDuration(start, start + 609_600));
	}
}
