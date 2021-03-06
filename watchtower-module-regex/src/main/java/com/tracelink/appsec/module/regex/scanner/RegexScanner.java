package com.tracelink.appsec.module.regex.scanner;

import com.tracelink.appsec.module.regex.model.RegexCustomRuleDto;
import com.tracelink.appsec.watchtower.core.benchmark.Benchmarker;
import com.tracelink.appsec.watchtower.core.benchmark.TimerType;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.processor.AbstractProcessor;
import com.tracelink.appsec.watchtower.core.scan.code.processor.CallableCreator;
import com.tracelink.appsec.watchtower.core.scan.code.processor.MultiThreadedProcessor;
import com.tracelink.appsec.watchtower.core.scan.code.processor.SingleThreadedProcessor;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanError;

/**
 * {@link ICodeScanner} implementation of a regex scan. Regex will scan every file using regex rules
 * that define patterns to find. If a pattern matches, a violation is logged.
 * <p>
 * Note: regexes are run line by line, so patterns that may match across lines will not match.
 *
 * @author csmith, mcool
 */
public class RegexScanner implements ICodeScanner {

	/**
	 * {@inheritDoc}
	 */
	@Override
	public CodeScanReport scan(CodeScanConfig config) {
		RegexBenchmarking benchmarking = new RegexBenchmarking();
		benchmarking.enable(config.isBenchmarkEnabled());

		CodeScanReport report = new CodeScanReport();
		try (Benchmarker totalTime =
				benchmarking.newBenchmarker(TimerType.DefaultTimerType.WALL_CLOCK)) {
			AbstractProcessor processor =
					getProcessor(config.getThreads(), benchmarking);

			try (Benchmarker b = benchmarking.newBenchmarker(TimerType.DefaultTimerType.SCAN)) {
				processor.runScan(config.getRuleset(), config.getWorkingDirectory());
			}

			try (Benchmarker reportTime =
					benchmarking.newBenchmarker(TimerType.DefaultTimerType.REPORT_GENERATE)) {
				processor.getReports().stream().forEach(report::join);
				processor.getSystemExceptions().stream()
						.forEach(exception -> new CodeScanError(exception));
			}
		}
		report.setRuleBenchmarking(benchmarking);
		return report;
	}

	protected AbstractProcessor getProcessor(int threads, RegexBenchmarking benchmarking) {
		if (threads > 0) {
			return new MultiThreadedProcessor(getCreator(benchmarking), threads);
		} else {
			return new SingleThreadedProcessor(getCreator(benchmarking));
		}
	}

	protected CallableCreator getCreator(RegexBenchmarking benchmarking) {
		return (file, ruleset) -> new RegexCallable(file, ruleset,
				benchmarking);
	}

	@Override
	public Class<? extends RuleDto> getSupportedRuleClass() {
		return RegexCustomRuleDto.class;
	}
}
