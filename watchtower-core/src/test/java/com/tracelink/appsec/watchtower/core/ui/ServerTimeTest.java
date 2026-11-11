package com.tracelink.appsec.watchtower.core.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.TimeZone;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResult;

/** UAT #9: a scan's time must reach the browser unchanged whatever the server's zone. */
class ServerTimeTest {
	private static final long FINISHED = 1_791_478_835_000L; // 2026-10-08T15:40:35Z
	private final TimeZone original = TimeZone.getDefault();

	@AfterEach
	void restoreZone() {
		TimeZone.setDefault(original);
	}

	@Test
	void scanEndTimeSurvivesTheServerZoneRoundTrip() {
		for (String zone : new String[] {"UTC", "Asia/Kolkata", "America/New_York"}) {
			TimeZone.setDefault(TimeZone.getTimeZone(zone));
			PullRequestScanEntity scan = new PullRequestScanEntity();
			scan.setEndDate(FINISHED);
			PRScanResult result = new PRScanResult();
			result.setDate(scan.getEndDate());

			assertEquals(FINISHED, result.getDateMillis(), zone);
		}
	}

	@Test
	void missingTimeIsZero() {
		assertEquals(0L, ServerTime.toEpochMillis(null));
	}
}
