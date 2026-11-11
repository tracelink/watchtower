package com.tracelink.appsec.module.json.scanner;

import com.tracelink.appsec.module.json.model.JsonRuleDto;
import com.tracelink.appsec.watchtower.core.benchmark.Benchmarker;
import com.tracelink.appsec.watchtower.core.benchmark.Benchmarking;
import com.tracelink.appsec.watchtower.core.benchmark.TimerType;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.EngineExecutionIdentity;
import com.tracelink.appsec.watchtower.core.scan.code.JavaEngineExecutionIdentity;
import com.tracelink.appsec.watchtower.core.scan.code.processor.AbstractProcessor;
import com.tracelink.appsec.watchtower.core.scan.code.processor.CallableCreator;
import com.tracelink.appsec.watchtower.core.scan.code.processor.MultiThreadedProcessor;
import com.tracelink.appsec.watchtower.core.scan.code.processor.SingleThreadedProcessor;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanError;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Scanner that processes a file as JSON and runs a JSONPath query against it.
 * 
 * @author csmith
 *
 */
public class JsonScanner implements ICodeScanner {
	@Override
	public EngineExecutionIdentity getExecutionIdentity(CodeScanConfig config) {
		if (getClass() != JsonScanner.class) return EngineExecutionIdentity.unknown("jsonpath-jackson");
		return JavaEngineExecutionIdentity.capture("jsonpath-jackson", this, config,
				JsonScanner.class, ICodeScanner.class, org.apache.commons.lang3.StringUtils.class,
				org.apache.commons.io.FileUtils.class, net.lingala.zip4j.ZipFile.class,
				org.yaml.snakeyaml.Yaml.class, com.jayway.jsonpath.JsonPath.class, com.fasterxml.jackson.core.JsonFactory.class,
				com.fasterxml.jackson.databind.ObjectMapper.class, com.fasterxml.jackson.annotation.JsonProperty.class,
				net.minidev.json.JSONValue.class, net.minidev.asm.BeansAccess.class, org.objectweb.asm.ClassReader.class);
	}

	@Override
	public CodeScanReport scan(CodeScanConfig config) {
		CodeScanReport report = new CodeScanReport();
		Benchmarking<JsonRuleDto> benchmarking = new Benchmarking<>();
		benchmarking.enable(config.isBenchmarkEnabled());

		try (Benchmarker totalTime =
				benchmarking.newBenchmarker(TimerType.DefaultTimerType.WALL_CLOCK)) {

			AbstractProcessor processor =
					getProcessor(config.getThreads()).withFileTypes(config.getFileTypes());

			try (Benchmarker scan = benchmarking.newBenchmarker(TimerType.DefaultTimerType.SCAN)) {
				processor.runScan(config.getRuleset(), config.getWorkingDirectory());
			}

			try (Benchmarker reportTime =
					benchmarking.newBenchmarker(TimerType.DefaultTimerType.REPORT_GENERATE)) {
				processor.getReports().stream().forEach(report::join);
				processor.getSystemExceptions().stream()
						.forEach(exception -> report.addError(new CodeScanError(exception)));
			}
		}
		report.setRuleBenchmarking(benchmarking);
		return report;
	}

	@Override
	public List<Class<? extends RuleDto>> getSupportedRuleClass() {
		return Collections.singletonList(JsonRuleDto.class);
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
