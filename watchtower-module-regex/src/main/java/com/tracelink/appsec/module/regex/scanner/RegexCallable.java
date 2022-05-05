package com.tracelink.appsec.module.regex.scanner;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.tracelink.appsec.module.regex.model.RegexCustomRuleDto;
import com.tracelink.appsec.watchtower.core.benchmark.Benchmarker;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanError;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanViolation;

/**
 * handles scanning a single file for regex matches based on rules
 *
 * @author csmith
 */
public class RegexCallable implements Callable<CodeScanReport> {

	private final Path currentFile;
	private final RulesetDto ruleset;
	private final RegexBenchmarking benchmarking;

	/**
	 * The source processor for Regex scans.
	 *
	 * @param currentFile  the file this code comes from
	 * @param ruleset      the ruleset to use in this scan
	 * @param benchmarking if applicable, the benchmarking tool
	 */
	public RegexCallable(Path currentFile, RulesetDto ruleset,
			RegexBenchmarking benchmarking) {
		this.currentFile = currentFile;
		this.ruleset = ruleset;
		this.benchmarking = benchmarking;
	}

	@Override
	public CodeScanReport call() {
		CodeScanReport report = new CodeScanReport();

		try (BufferedReader br = new BufferedReader(new FileReader(currentFile.toFile()))) {
			String lineData;
			int lineNum = 0;
			while ((lineData = br.readLine()) != null) {
				lineNum++;
				for (RuleDto rule : ruleset.getAllRules()) {
					if (rule instanceof RegexCustomRuleDto) {
						RegexCustomRuleDto regexRule = (RegexCustomRuleDto) rule;
						if (regexRule.isValidExtension(currentFile.toString())) {
							if (findViolations(lineData, regexRule)) {
								CodeScanViolation sv = new CodeScanViolation();
								sv.setViolationName(regexRule.getName());
								sv.setFileName(currentFile.toString());
								sv.setLineNum(lineNum);
								sv.setSeverity(regexRule.getPriority());
								sv.setMessage(regexRule.getMessage());
								report.addViolation(sv);
							}
						}
					}
				}
			}
		} catch (IOException e) {
			report.addError(new CodeScanError("Could not read: " + currentFile.getFileName()));
		}

		return report;
	}

	private boolean findViolations(String lineData, RegexCustomRuleDto regexRule) {
		try (Benchmarker b = benchmarking.newRuleBenchmarker(regexRule)) {
			Pattern regexPattern = regexRule.getCompiledPattern();
			Matcher matcher = regexPattern.matcher(lineData);
			return matcher.find();
		}
	}

}
