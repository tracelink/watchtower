package com.tracelink.appsec.module.json.scanner;

import com.tracelink.appsec.module.json.model.JsonRuleDto;
import com.tracelink.appsec.watchtower.core.benchmark.Benchmarker;
import com.tracelink.appsec.watchtower.core.benchmark.Benchmarking;
import com.tracelink.appsec.watchtower.core.benchmark.TimerType;
import com.tracelink.appsec.watchtower.core.module.scanner.AbstractScmScanner;
import com.tracelink.appsec.watchtower.core.report.ScanError;
import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.scan.processor.AbstractProcessor;
import com.tracelink.appsec.watchtower.core.scan.processor.CallableCreator;
import com.tracelink.appsec.watchtower.core.scan.processor.MultiThreadedProcessor;
import com.tracelink.appsec.watchtower.core.scan.processor.SingleThreadedProcessor;
import com.tracelink.appsec.watchtower.core.scan.scm.ScmScanConfig;

/**
 * Scanner that processes a file as JSON and runs a JSONPath query against it.
 * 
 * @author csmith
 *
 */
public class JsonScanner extends AbstractScmScanner {

	@Override
	public ScanReport scan(ScmScanConfig config) {
		ScanReport report = new ScanReport();
		Benchmarking<JsonRuleDto> benchmarking = new Benchmarking<>();
		benchmarking.enable(config.isBenchmarkEnabled());

		try (Benchmarker totalTime =
				benchmarking.newBenchmarker(TimerType.DefaultTimerType.WALL_CLOCK)) {

			AbstractProcessor processor =
					getProcessor(config.getThreads());

			try (Benchmarker scan = benchmarking.newBenchmarker(TimerType.DefaultTimerType.SCAN)) {
				processor.runScan(config.getRuleset(), config.getWorkingDirectory());
			}

			try (Benchmarker reportTime =
					benchmarking.newBenchmarker(TimerType.DefaultTimerType.REPORT_GENERATE)) {
				processor.getReports().stream().forEach(report::join);
				processor.getSystemExceptions().stream()
						.forEach(exception -> report.addError(new ScanError(exception)));
			}
		}
		report.setRuleBenchmarking(benchmarking);
		return report;
	}

	@Override
	public Class<? extends RuleDto> getSupportedRuleClass() {
		return JsonRuleDto.class;
	}

	private AbstractProcessor getProcessor(int threads) {
		if (threads > 0) {
			return new MultiThreadedProcessor(getCreator(), threads);
		}
		return new SingleThreadedProcessor(getCreator());
	}

	private CallableCreator getCreator() {
		return (file, ruleset) -> new JsonCallable(file, ruleset);
	}

}
