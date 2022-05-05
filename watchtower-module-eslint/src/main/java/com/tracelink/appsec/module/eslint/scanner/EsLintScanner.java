package com.tracelink.appsec.module.eslint.scanner;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.io.FileUtils;

import com.google.gson.Gson;
import com.tracelink.appsec.module.eslint.engine.LinterEngine;
import com.tracelink.appsec.module.eslint.engine.ProcessResult;
import com.tracelink.appsec.module.eslint.engine.json.LinterMessage;
import com.tracelink.appsec.module.eslint.interpreter.EsLintRulesetExporter;
import com.tracelink.appsec.module.eslint.model.EsLintCustomRuleDto;
import com.tracelink.appsec.module.eslint.model.EsLintRuleDto;
import com.tracelink.appsec.watchtower.core.benchmark.Benchmarker;
import com.tracelink.appsec.watchtower.core.benchmark.Benchmarking;
import com.tracelink.appsec.watchtower.core.benchmark.TimerType;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetException;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.processor.AbstractProcessor;
import com.tracelink.appsec.watchtower.core.scan.code.processor.CallableCreator;
import com.tracelink.appsec.watchtower.core.scan.code.processor.MultiThreadedProcessor;
import com.tracelink.appsec.watchtower.core.scan.code.processor.SingleThreadedProcessor;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanError;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanViolation;

/**
 * {@link ICodeScanner} for ESLint. Scans and reports with the ESLint Linter via the
 * {@link LinterEngine}.
 *
 * @author mcool
 */
public class EsLintScanner implements ICodeScanner {

	private static final Gson GSON = new Gson();
	private final LinterEngine engine;

	public EsLintScanner(LinterEngine engine) {
		this.engine = engine;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public CodeScanReport scan(CodeScanConfig config) {
		CodeScanReport report = new CodeScanReport();
		Benchmarking<EsLintCustomRuleDto> benchmarking = new Benchmarking<>();
		benchmarking.enable(config.isBenchmarkEnabled());

		try (Benchmarker totalTime = benchmarking
				.newBenchmarker(TimerType.DefaultTimerType.WALL_CLOCK)) {
			// Write ESLint ruleset to JS file
			Path rulesetPath;
			try {
				rulesetPath = writeRulesetToFile(config.getRuleset());
			} catch (IOException | RulesetException e) {
				report.addError(
						new CodeScanError(
								"Exception writing ESLint ruleset to file: " + e.getMessage()));
				return report;
			}

			// Run processor
			AbstractProcessor processor = getProcessor(config, rulesetPath);

			try (Benchmarker b = benchmarking.newBenchmarker(TimerType.DefaultTimerType.SCAN)) {
				processor.runScan(config.getRuleset(), config.getWorkingDirectory());
			}

			try (Benchmarker reportTime =
					benchmarking.newBenchmarker(TimerType.DefaultTimerType.REPORT_GENERATE)) {
				processor.getReports().forEach(report::join);
				processor.getSystemExceptions()
						.forEach(exception -> report.addError(new CodeScanError(exception)));
			}
			// Delete ruleset file
			FileUtils.deleteQuietly(rulesetPath.toFile());
		}

		report.setRuleBenchmarking(benchmarking);
		return report;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Class<? extends RuleDto> getSupportedRuleClass() {
		return EsLintCustomRuleDto.class;
	}

	/**
	 * Writes the custom ESLint rule definitions to a temporary JavaScript file. The caller of this
	 * method is responsible for deleting the file.
	 *
	 * @param ruleset ruleset containing ESLint rules
	 * @return path to the ruleset definition file
	 * @throws IOException if an I/O exception is thrown while creating or writing to the file
	 */
	private Path writeRulesetToFile(RulesetDto ruleset)
			throws IOException, RulesetException {
		String uri = "ruleset-" + ruleset.getId();
		Path rulesetPath = Files.createTempFile(uri, ".js").toFile().getCanonicalFile()
				.getAbsoluteFile().toPath();
		try (InputStream is = new EsLintRulesetExporter().exportRuleset(ruleset)) {
			Files.copy(is, rulesetPath, StandardCopyOption.REPLACE_EXISTING);
		}
		return rulesetPath;
	}

	private AbstractProcessor getProcessor(CodeScanConfig config, Path rulesetPath) {
		int threads = config.getThreads();
		if (threads > 0) {
			return new MultiThreadedProcessor(getCreator(config.getWorkingDirectory(), rulesetPath),
					threads);
		} else {
			return new SingleThreadedProcessor(
					getCreator(config.getWorkingDirectory(), rulesetPath));
		}
	}

	private CallableCreator getCreator(Path workingDirectory, Path rulesetPath) {
		return (path, ruleset) -> () -> {
			// Create ESLint report
			CodeScanReport report = new CodeScanReport();
			try (BufferedReader br = new BufferedReader(new FileReader(path.toFile()))) {
				Path filePath = path.getFileName();
				Path directoryPath = workingDirectory.relativize(path.getParent());
				// Run Linter on all lines of the file
				ProcessResult scanResult =
						engine.scanCode(br.lines().collect(Collectors.joining("\n")),
								directoryPath.toString(), filePath.toString(),
								rulesetPath.toString());
				// Check for errors
				if (scanResult.hasErrors()) {
					report.addError(new CodeScanError(scanResult.getErrors()));
				}
				// Process results of scan
				if (scanResult.hasResults()) {
					List<LinterMessage> messages = GSON.fromJson(scanResult.getResults(),
							LinterEngine.MESSAGES_TYPE_TOKEN.getType());
					// Process ESLint messages and add scan violations or errors
					processMessages(messages, report, ruleset, path);
				}
			} catch (IOException e) {
				report.addError(new CodeScanError("Could not read: " + path.getFileName()));
			}
			return report;
		};
	}

	/**
	 * Processes the given messages to add scan violations and scan errors to the given report. The
	 * given ruleset is used to assign some values of the scan violations.
	 *
	 * @param messages the messages to process
	 * @param report   the ESLint report to add errors and violations to
	 * @param ruleset  the ruleset used to produce the given messages
	 * @param fileName the name of the file scanned for these messages
	 */
	private static void processMessages(List<LinterMessage> messages, CodeScanReport report,
			RulesetDto ruleset, Path fileName) {
		Set<RuleDto> esLintRules = ruleset.getAllRules().stream()
				.filter(r -> r instanceof EsLintRuleDto).collect(Collectors.toSet());
		for (LinterMessage message : messages) {
			// Message is an error
			if (message.isFatal() || message.getNodeType() == null || message.getSeverity() != 1
					|| message.getRuleId() == null) {
				// Add error to report
				report.addError(new CodeScanError(message.getMessage()));
			}
			// Message is a violation
			else {
				RuleDto rule = esLintRules.stream()
						.filter(r -> r.getName().equals(message.getRuleId()))
						.findFirst().orElse(null);
				// There is no corresponding ESLint rule for this violation
				if (rule == null) {
					continue;
				}
				// Create scan violation
				CodeScanViolation violation = new CodeScanViolation();
				violation.setViolationName(message.getRuleId());
				violation.setFileName(fileName.toString());
				violation.setLineNum(message.getLine());
				violation.setSeverity(rule.getPriority());
				violation.setMessage(message.getMessage());
				// Add violation to report
				report.addViolation(violation);
			}
		}
	}
}
