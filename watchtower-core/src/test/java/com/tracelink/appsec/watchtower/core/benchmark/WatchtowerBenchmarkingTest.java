package com.tracelink.appsec.watchtower.core.benchmark;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class WatchtowerBenchmarkingTest {

	@Test
	public void testDisabled() {
		WatchtowerBenchmarking bench = new WatchtowerBenchmarking("");
		bench.enable(false);
		Assertions.assertNull(bench.report(""));
	}

	@Test
	public void testReportAll() {
		WatchtowerBenchmarking bench = new WatchtowerBenchmarking("123");
		bench.enable(true);

		bench.newBenchmarker(WatchtowerTimers.SCAN_TEST_SETUP).close();
		bench.newBenchmarker(WatchtowerTimers.SCAN_ALL_SCANNERS).close();
		bench.newBenchmarker(WatchtowerTimers.SEND_REPORT).close();

		String report = bench.report("\n");
		for (WatchtowerTimers timer : WatchtowerTimers.values()) {
			Assertions.assertTrue(report.contains(timer.getExternalName()));
		}
	}

}
