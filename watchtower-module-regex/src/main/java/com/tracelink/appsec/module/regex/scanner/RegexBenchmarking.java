package com.tracelink.appsec.module.regex.scanner;

import java.util.Map.Entry;

import com.tracelink.appsec.module.regex.model.RegexRuleDto;
import com.tracelink.appsec.watchtower.core.benchmark.Benchmark;
import com.tracelink.appsec.watchtower.core.benchmark.Benchmarking;

/**
 * Benchmarker implementation for Regex Rules. Adds Regex Rule-specific timers to benchmarking
 *
 * @author csmith
 */
public class RegexBenchmarking extends Benchmarking<RegexRuleDto> {

	@Override
	protected void outputRuleTimers(String linesep, StringBuilder sb) {
		int nameSize = "Rule Name".length();
		int timeSize = "Time Spent".length();
		int callSize = "Num Calls".length();
		for (Entry<RegexRuleDto, Benchmark> entry : getRuleBenchmarks().entrySet()) {
			nameSize = Math.max(nameSize, entry.getKey().getName().length());
			timeSize = Math.max(timeSize, String.valueOf(entry.getValue().getTotalTime()).length());
			callSize = Math.max(callSize, String.valueOf(entry.getValue().getCallCount()).length());
		}
		String format = "%-" + nameSize + "s   %-" + timeSize + "s   %-" + callSize + "s";
		sb.append(String.format(format, "Rule Name", "Time Spent", "Num Calls")).append(linesep);
		for (Entry<RegexRuleDto, Benchmark> entry : getRuleBenchmarks().entrySet()) {
			sb.append(
					String.format(format, entry.getKey().getName(), entry.getValue().getTotalTime(),
							entry.getValue().getCallCount()))
					.append(linesep);
		}
	}
}
