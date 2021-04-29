package com.tracelink.appsec.watchtower.core.benchmark;

/**
 * manages a benchmark object's lifecycle using the {@code AutoCloseable} flow
 * 
 * @author csmith
 *
 */
public class Benchmarker implements AutoCloseable {
	private Benchmark benchmark;
	private long start;
	private long end;

	Benchmarker() {
		// used for no-op benchmarking
	}

	/**
	 * begin a benchmarking
	 * 
	 * @param benchmark the benchmark to use
	 */
	public Benchmarker(Benchmark benchmark) {
		start = System.currentTimeMillis();
		this.benchmark = benchmark;
	}

	/**
	 * end a benchmarking
	 */
	@Override
	public void close() {
		end = System.currentTimeMillis();
		this.benchmark.add(end - start);
	}
}
