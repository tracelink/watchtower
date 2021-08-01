package com.tracelink.appsec.module.checkov.scanner;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.tracelink.appsec.module.checkov.engine.CheckovEngine;
import com.tracelink.appsec.module.checkov.model.CheckovProvidedRuleDto;
import com.tracelink.appsec.watchtower.core.benchmark.Benchmarker;
import com.tracelink.appsec.watchtower.core.benchmark.Benchmarking;
import com.tracelink.appsec.watchtower.core.benchmark.TimerType;
import com.tracelink.appsec.watchtower.core.module.scanner.IScanner;
import com.tracelink.appsec.watchtower.core.report.ScanError;
import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.report.ScanViolation;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.ScanConfig;

/**
 * {@link IScanner} for Checkov. Executes the {@linkplain CheckovEngine} and publishes the results
 *
 * @author csmith
 */
public class CheckovScanner implements IScanner {
	private static final Logger LOGGER = LoggerFactory.getLogger(CheckovScanner.class);
	private final CheckovEngine engine;

	public CheckovScanner(CheckovEngine engine) {
		this.engine = engine;
	}

	@Override
	public ScanReport scan(ScanConfig config) {
		ScanReport report = new ScanReport();
		Benchmarking<CheckovProvidedRuleDto> benchmarking = new Benchmarking<>();
		benchmarking.enable(config.isBenchmarkEnabled());

		// Run processor
		try (Benchmarker totalTime = benchmarking
				.newBenchmarker(TimerType.DefaultTimerType.WALL_CLOCK)) {

			List<CheckovProvidedRuleDto> checkovRules = getCheckovRules(config.getRuleset());

			JsonObject result;
			try (Benchmarker scanTime =
					benchmarking.newBenchmarker(TimerType.DefaultTimerType.SCAN)) {
				result = engine.runCheckovDirectoryScan(config.getWorkingDirectory(), checkovRules);
			}

			try (Benchmarker reportTime =
					benchmarking.newBenchmarker(TimerType.DefaultTimerType.REPORT_GENERATE)) {
				addResultsToReport(result, checkovRules, report, config.getWorkingDirectory());
			}
		} catch (Exception e) {
			LOGGER.error("Exception while scanning", e);
			report.addError(new ScanError("Error while scanning: " + e.getMessage()));
		}

		report.setRuleBenchmarking(benchmarking);
		return report;
	}

	private List<CheckovProvidedRuleDto> getCheckovRules(RulesetDto ruleset) {
		List<CheckovProvidedRuleDto> checkovRules = ruleset.getAllRules().stream()
				.filter(r -> r instanceof CheckovProvidedRuleDto)
				.map(r -> (CheckovProvidedRuleDto) r)
				.collect(Collectors.toList());

		return checkovRules;
	}

	private void addResultsToReport(JsonObject result, List<CheckovProvidedRuleDto> rules,
			ScanReport report, Path workingDirectory) {
		if (result.has("errors")) {
			report.addError(
					new ScanError("Runtime error(s) found: " + result.get("errors").getAsString()));
		}
		if (result.has("results")) {
			JsonObject results = result.getAsJsonObject("results");
			if (results.has("failed_checks")) {
				JsonArray failed = results.getAsJsonArray("failed_checks");
				failed.forEach(f -> {
					if (f.isJsonObject()) {
						JsonObject fail = f.getAsJsonObject();
						String failName = fail.get("check_id").getAsString();
						Optional<CheckovProvidedRuleDto> foundRule = rules.stream()
								.filter(r -> r.getCheckovRuleName().equals(failName)).findFirst();
						if (foundRule.isPresent()) {
							RuleDto rule = foundRule.get();
							ScanViolation violation = new ScanViolation();
							violation.setFileName(workingDirectory
									.resolve(fail.get("file_path").getAsString().substring(1))
									.toString());
							JsonArray lines = fail.getAsJsonArray("file_line_range");
							violation.setLineNum(Integer.parseInt(lines.get(0).toString()));
							violation.setMessage(
									rule.getMessage() + " More Info: " + rule.getExternalUrl());
							violation.setSeverity(rule.getPriority().getName());
							violation.setSeverityValue(rule.getPriority().getPriority());
							violation.setViolationName(failName);
							report.addViolation(violation);
						} else {
							String error = "Could not find rule for check " + failName;
							LOGGER.error(error);
							report.addError(new ScanError(error));
						}
					} else {
						LOGGER.error("Checkov failed check is not JSON: " + f.toString());
					}
				});
			}
		}
	}

	@Override
	public Class<? extends RuleDto> getSupportedRuleClass() {
		return CheckovProvidedRuleDto.class;
	}

}
