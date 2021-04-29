package com.tracelink.appsec.watchtower.core.benchmark;

import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;

/**
 * manages all benchmarks for a given execution.
 * 
 * @author csmith
 * 
 * @param <T> the type to use as a rule benchmarker key
 */
public class Benchmarking<T> {
	private Map<TimerType, Benchmark> benchmarks = new ConcurrentHashMap<>();
	private Map<T, Benchmark> ruleBenchmarks = new ConcurrentHashMap<>();
	private boolean shouldMark = false;

	/**
	 * create a new benchmark for a known {@code TimerType}
	 * 
	 * @param type the type of the timer to track
	 * @return the benchmark manager
	 */
	public Benchmarker newBenchmarker(TimerType type) {
		if (!shouldMark) {
			return new NopBenchmarker();
		}

		Benchmark bench = benchmarks.get(type);
		if (bench == null) {
			bench = new Benchmark();
			benchmarks.put(type, bench);
		}
		return new Benchmarker(bench);
	}

	protected Map<TimerType, Benchmark> getBenchmarks() {
		return benchmarks;
	}

	/**
	 * create a new rule benchmark for some rule
	 * 
	 * @param rule the rule to track against
	 * @return a benchmark manager for this rule
	 */
	public Benchmarker newRuleBenchmarker(T rule) {
		if (!shouldMark) {
			return new NopBenchmarker();
		}

		Benchmark bench = ruleBenchmarks.get(rule);
		if (bench == null) {
			bench = new Benchmark();
			ruleBenchmarks.put(rule, bench);
		}
		return new Benchmarker(bench);
	}

	protected Map<T, Benchmark> getRuleBenchmarks() {
		return ruleBenchmarks;
	}

	/**
	 * Enable or disable benchmarking
	 * 
	 * @param benchmark true to enable benchmark gathering, false to ignore gathering
	 */
	public void enable(boolean benchmark) {
		shouldMark = benchmark;
	}

	public boolean isEnabled() {
		return shouldMark;
	}

	/**
	 * create a report string for all benchmarks in this object
	 * 
	 * @param linesep to separate items in the benchmark
	 * @return a string report for all benchmarks in this execution
	 */
	public String report(String linesep) {
		if (!shouldMark) {
			return null;
		}
		StringBuilder sb = new StringBuilder();
		sb.append("Benchmark").append(linesep).append(linesep);
		sb.append("Timers").append(linesep);
		outputTimers(sb, linesep);
		sb.append(linesep);
		sb.append("Rule Timers").append(linesep);
		outputRuleTimers(linesep, sb);
		return sb.toString();
	}

	/**
	 * Overrideable. Use this to report on individual rule timers
	 * 
	 * @param linesep to separate items in the benchmark
	 * @param sb      the {@code StringBuilder} to use to add report data to
	 */
	protected void outputRuleTimers(String linesep, StringBuilder sb) {
		// Overrideable
	}

	/**
	 * report on all known timers for this execution
	 * 
	 * @param sb      the {@code StringBuilder} to use to add report data to
	 * @param linesep to separate items in the benchmark
	 */
	protected void outputTimers(StringBuilder sb, String linesep) {
		int nameSize = "Name".length();
		int timeSize = "Time Spent".length();
		int callSize = "Num Calls".length();
		for (Entry<TimerType, Benchmark> entry : this.benchmarks.entrySet()) {
			nameSize = Math.max(nameSize, entry.getKey().getExternalName().length());
			timeSize = Math.max(timeSize, String.valueOf(entry.getValue().getTotalTime()).length());
			callSize = Math.max(callSize, String.valueOf(entry.getValue().getCallCount()).length());
		}
		String format = "%-" + nameSize + "s   %-" + timeSize + "s   %-" + callSize + "s";
		sb.append(String.format(format, "Name", "Time Spent", "Num Calls")).append(linesep);
		for (Entry<TimerType, Benchmark> entry : this.benchmarks.entrySet()) {
			sb.append(String.format(format, entry.getKey().getExternalName(),
					entry.getValue().getTotalTime(),
					entry.getValue().getCallCount())).append(linesep);
		}
	}

	/**
	 * This is used to quickly disregard benchmark events if benchmarking is not enabled
	 * 
	 * @author csmith
	 *
	 */
	static class NopBenchmarker extends Benchmarker {
		NopBenchmarker() {
			super();
		}

		@Override
		public void close() {
			// no-op
		}
	}

}
