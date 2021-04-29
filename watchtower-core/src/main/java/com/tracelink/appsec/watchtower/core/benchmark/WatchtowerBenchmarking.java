package com.tracelink.appsec.watchtower.core.benchmark;

import java.util.Arrays;
import java.util.List;
import java.util.Map.Entry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Benchmarking interface for a Watchtower scan
 *
 * @author csmith
 */
public class WatchtowerBenchmarking extends Benchmarking<Object> {
	private static Logger LOG = LoggerFactory.getLogger(WatchtowerBenchmarking.class);
	private String id;

	/**
	 * instantiate a benchmarking with an id for the report
	 *
	 * @param scanName the id of this report
	 */
	public WatchtowerBenchmarking(String scanName) {
		this.id = scanName;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String report(String linesep) {
		if (!isEnabled()) {
			return null;
		}
		StringBuilder sb = new StringBuilder();
		sb.append("Benchmark Report for ").append(id).append(linesep).append(linesep);
		sb.append("Timers").append(linesep);
		outputTimers(sb, linesep);
		sb.append(linesep);
		String output = sb.toString();
		LOG.info(output);
		return output;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void outputTimers(StringBuilder sb, String linesep) {
		int nameSize = "Name".length();
		int timeSize = "Time Spent(ms)".length();
		int callSize = "Num Calls".length();
		for (Entry<TimerType, Benchmark> entry : getBenchmarks().entrySet()) {
			nameSize = Math.max(nameSize, entry.getKey().getExternalName().length());
			timeSize = Math.max(timeSize, String.valueOf(entry.getValue().getTotalTime()).length());
			callSize = Math.max(callSize, String.valueOf(entry.getValue().getCallCount()).length());
		}
		List<TimerType> timerOrder = Arrays.asList(WatchtowerTimers.values());
		String format = "%-" + nameSize + "s   %-" + timeSize + "s   %-" + callSize + "s";
		sb.append(String.format(format, "Name", "Time Spent(ms)", "Num Calls")).append(linesep);
		for (TimerType t : timerOrder) {
			Benchmark bench = getBenchmarks().get(t);
			sb.append(String.format(format, t.getExternalName(), bench.getTotalTime(),
					bench.getCallCount()))
					.append(linesep);
		}
	}

}
