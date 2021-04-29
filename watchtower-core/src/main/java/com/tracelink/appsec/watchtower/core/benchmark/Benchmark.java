package com.tracelink.appsec.watchtower.core.benchmark;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Holds information about a given Benchmark's time spent and number of times called
 * 
 * @author csmith
 *
 */
public class Benchmark {
	private AtomicLong total = new AtomicLong();
	private AtomicLong callCount = new AtomicLong();

	public long getTotalTime() {
		return total.get();
	}

	public long getCallCount() {
		return this.callCount.get();
	}

	void add(long timer) {
		total.addAndGet(timer);
		callCount.incrementAndGet();
	}
}
