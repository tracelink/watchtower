package com.tracelink.appsec.watchtower.core.scan;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary.ScannerExecution;
import java.util.List;
import org.junit.jupiter.api.Test;

class ScanExecutionSummaryTest {
	@Test
	void reportsRanAndSkippedScannerCountsAndRoundTripsJson() {
		List<ScannerExecution> scanners = List.of(
				new ScannerExecution("PMD", "RAN", 42, null),
				new ScannerExecution("Advisory", "SKIPPED", 0, "No compatible rules"),
				new ScannerExecution("Regex", "FAILED", 10, null),
				new ScannerExecution("ESLint", "REUSED", 0, "Reused report"),
    new ScannerExecution("Opengrep", "DISABLED", 0, "Module disabled"),
    new ScannerExecution("Unknown targets", "UNSUPPORTED", 0, "No eligible targets"));
		ScanExecutionSummary summary = new ScanExecutionSummary(17, scanners);

		assertTrue(summary.isRecorded());
		assertEquals(1, summary.getRanCount());
		assertEquals(1, summary.getSkippedCount());
		assertEquals(1, summary.getFailedCount());
		assertEquals(1, summary.getReusedCount());
  assertEquals(1, summary.getDisabledCount());assertEquals(1, summary.getUnsupportedCount());
		assertEquals(scanners, ScanExecutionSummaryCodec.decode(
				ScanExecutionSummaryCodec.encode(scanners)));
	}

	@Test
	void aScannerWithNoMatchingFilesIsCountedAndLabelledNotNeeded() {
		ScannerExecution notNeeded = new ScannerExecution("Checkov", "NOT_APPLICABLE", 0, "No .tf files in this scan");
		ScanExecutionSummary summary = new ScanExecutionSummary(3, List.of(new ScannerExecution("PMD", "RAN", 1, null), notNeeded));

		assertEquals(1, summary.getNotApplicableCount());
		assertEquals(0, summary.getSkippedCount());
		assertEquals("Not needed", notNeeded.getLabel());
		assertEquals("neutral", notNeeded.getTone());
	}
}
