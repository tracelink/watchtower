package com.tracelink.appsec.watchtower.core.benchmark;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class BenchmarkTest {

	@Test
	public void testBenchmarkIncrements() {
		Benchmark b = new Benchmark();
		long timerIncrement = 15;
		for (long i = 1L; i < 3L; i++) {
			b.add(timerIncrement);
			Assertions.assertEquals(timerIncrement * i, b.getTotalTime());
			Assertions.assertEquals(i, b.getCallCount());
		}
	}

}
