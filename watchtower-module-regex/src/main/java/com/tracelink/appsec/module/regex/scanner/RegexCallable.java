package com.tracelink.appsec.module.regex.scanner;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;

import com.tracelink.appsec.module.regex.model.RegexCustomRuleDto;
import com.tracelink.appsec.module.regex.model.RegexProvidedRuleDto;
import com.tracelink.appsec.module.regex.model.RegexRuleDto;
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

	/** The longest one rule may spend on one line before it is stopped for the rest of the file. */
	private static final long DEFAULT_MATCH_TIMEOUT_NANOS = TimeUnit.SECONDS.toNanos(2);

	private final Path currentFile;
	private final RulesetDto ruleset;
	private final RegexBenchmarking benchmarking;
	private final long matchTimeoutNanos;
	private final Set<String> stoppedRules = new LinkedHashSet<>();

	/**
	 * The source processor for Regex scans.
	 *
	 * @param currentFile  the file this code comes from
	 * @param ruleset      the ruleset to use in this scan
	 * @param benchmarking if applicable, the benchmarking tool
	 */
	public RegexCallable(Path currentFile, RulesetDto ruleset,
			RegexBenchmarking benchmarking) {
		this(currentFile, ruleset, benchmarking, DEFAULT_MATCH_TIMEOUT_NANOS);
	}

	RegexCallable(Path currentFile, RulesetDto ruleset, RegexBenchmarking benchmarking,
			long matchTimeoutNanos) {
		this.currentFile = currentFile;
		this.ruleset = ruleset;
		this.benchmarking = benchmarking;
		this.matchTimeoutNanos = matchTimeoutNanos;
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
								addViolationToReport(report, regexRule, lineNum);
							}
						}
					} else if (rule instanceof RegexProvidedRuleDto) {
						RegexProvidedRuleDto regexRule = (RegexProvidedRuleDto) rule;
						if (regexRule.isValidExtension(currentFile.toString())) {
							if (findViolations(lineData, regexRule)) {
								addViolationToReport(report, regexRule, lineNum);
							}
						}
					}
				}
			}
		} catch (IOException e) {
			report.addError(new CodeScanError("Could not read: " + currentFile.getFileName()));
		}
		stoppedRules.forEach(name -> report.addError(new CodeScanError("Rule \"" + name
				+ "\" was stopped because it took too long to match in " + currentFile.getFileName())));

		return report;
	}

	private boolean findViolations(String lineData, RegexCustomRuleDto regexRule) {
		try (Benchmarker b = benchmarking.newRuleBenchmarker(regexRule)) {
			return boundedFind(regexRule, lineData);
		}
	}

	//	removing Benchmarking for provided rules for now as more refactoring is needed to achieve it
	private boolean findViolations(String lineData, RegexProvidedRuleDto regexRule) {
		return boundedFind(regexRule, lineData);
	}

	/**
	 * Looks for the rule's pattern in the line, but gives up on a pattern that backtracks without
	 * end: that rule is skipped for the rest of the file and reported once.
	 */
	private boolean boundedFind(RegexRuleDto regexRule, String lineData) {
		if (stoppedRules.contains(regexRule.getName())) {
			return false;
		}
		try {
			Matcher matcher = regexRule.getCompiledPattern().matcher(
					new DeadlineCharSequence(lineData, System.nanoTime() + matchTimeoutNanos));
			return matcher.find();
		} catch (DeadlineCharSequence.MatchTimeoutException tooSlow) {
			stoppedRules.add(regexRule.getName());
			return false;
		}
	}

	private void addViolationToReport(CodeScanReport report, RegexRuleDto regexRule, int lineNum) {
		CodeScanViolation sv = new CodeScanViolation();
		sv.setRuleIdentity(regexRule.getExecutionIdentity());
		sv.setViolationName(regexRule.getName());
		sv.setFileName(currentFile.toString());
		sv.setLineNum(lineNum);
		sv.setSeverity(regexRule.getPriority());
		sv.setMessage(regexRule.getMessage());
		report.addViolation(sv);
	}
}
