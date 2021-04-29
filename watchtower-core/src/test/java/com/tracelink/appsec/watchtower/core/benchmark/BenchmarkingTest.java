package com.tracelink.appsec.watchtower.core.benchmark;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.benchmark.Benchmarking.NopBenchmarker;
import com.tracelink.appsec.watchtower.core.benchmark.TimerType.DefaultTimerType;

public class BenchmarkingTest {

	@Test
	public void testDisabledBenchmarking() {
		Benchmarking<Object> bmarking = new Benchmarking<>();
		bmarking.enable(false);
		Assertions.assertEquals(false, bmarking.isEnabled());
		Assertions.assertEquals(NopBenchmarker.class,
				bmarking.newBenchmarker(DefaultTimerType.WALL_CLOCK).getClass());
		Assertions.assertEquals(NopBenchmarker.class,
				bmarking.newRuleBenchmarker(new Object()).getClass());
		try (Benchmarker b = bmarking.newBenchmarker(DefaultTimerType.SCAN)) {
			// normally do work here
		}
		Assertions.assertEquals(null, bmarking.report(""));
	}

	@Test
	public void testDefaultBenchmarkingReports() {
		Benchmarking<Object> bmarking = new Benchmarking<Object>();
		bmarking.enable(true);

		// benchmarking works once
		Benchmarker bmarker = bmarking.newBenchmarker(DefaultTimerType.WALL_CLOCK);
		bmarker.close();
		Assertions.assertTrue(
				bmarking.report(" ").contains(DefaultTimerType.WALL_CLOCK.getExternalName()));

		// can re-use benchmarking
		bmarker = bmarking.newBenchmarker(DefaultTimerType.WALL_CLOCK);
		bmarker.close();
		Assertions.assertTrue(
				bmarking.report(" ").contains(DefaultTimerType.WALL_CLOCK.getExternalName()));
	}

	@Test
	public void testRuleBenchmarking() {
		Benchmarking<String> bmarking = new Benchmarking<String>();
		bmarking.enable(true);
		String ruleName = "someRuleName";

		// benchmarking works once
		Benchmarker bmarker = bmarking.newRuleBenchmarker(ruleName);
		bmarker.close();
		Assertions.assertEquals(1L, bmarking.getRuleBenchmarks().get(ruleName).getCallCount());

		// can re-use benchmarking
		bmarker = bmarking.newRuleBenchmarker(ruleName);
		bmarker.close();
		Assertions.assertEquals(2L, bmarking.getRuleBenchmarks().get(ruleName).getCallCount());
	}

}
