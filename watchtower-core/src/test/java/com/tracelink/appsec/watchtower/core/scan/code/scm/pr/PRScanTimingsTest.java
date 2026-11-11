package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class PRScanTimingsTest {

	@Test
	public void testTimingsDefensivelyCopyScannerEntriesAndClampNegativeValues() {
		List<PRScanTimings.ScannerTiming> scanners =
				new ArrayList<>(List.of(new PRScanTimings.ScannerTiming("RegexScanner", 25)));
		PRScanTimings timings = new PRScanTimings(-1, 100, 10, 30, 20, 15, 20, 5,
				2, "CHANGED_FILES", "INDIVIDUAL_FILES", scanners, true);
		scanners.clear();

		Assertions.assertEquals(0, timings.queueWaitMs());
		Assertions.assertEquals(1, timings.scanners().size());
		Assertions.assertThrows(UnsupportedOperationException.class,
				() -> timings.scanners().add(new PRScanTimings.ScannerTiming("Other", 1)));
	}

	@Test
	public void testScannerTimingRejectsBlankName() {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> new PRScanTimings.ScannerTiming(" ", 1));
	}

	@Test
	public void testAScannerThatRanWithErrorsIsOneEntryNotTwo() {
		String timings = "[{\"scannerName\":\"com.tracelink.appsec.module.pmd.scanner.PMDScanner\",\"durationMs\":9400}]";
		String executions = com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummaryCodec.encode(List.of(
				new com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary.ScannerExecution("PMD", "FAILED", 0,
						null)));

		var merged = PRScanTimings.executions(timings, executions);

		Assertions.assertEquals(1, merged.size());
		Assertions.assertEquals("FAILED", merged.get(0).status());
		Assertions.assertEquals(9400, merged.get(0).durationMs());
	}
}
