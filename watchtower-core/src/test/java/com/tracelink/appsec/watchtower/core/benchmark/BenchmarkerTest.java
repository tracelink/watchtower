package com.tracelink.appsec.watchtower.core.benchmark;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class BenchmarkerTest {

	@Test
	public void testBenchmarkerBenchmark() throws Exception {
		Benchmark b = new Benchmark();
		Benchmarker bmarker = new Benchmarker(b);
		long sleepTime = 100L;
		Thread.sleep(sleepTime);
		bmarker.close();
		Assertions.assertEquals(1L, b.getCallCount());
		Assertions.assertTrue(b.getTotalTime() > 0 && b.getTotalTime() > sleepTime / 2);
	}

}
