package com.tracelink.appsec.module.regex.scanner;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.tracelink.appsec.module.regex.model.RegexCustomRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;

@ExtendWith(MockitoExtension.class)
public class RegexCallableTest {

	@Mock
	RulesetDto ruleset;

	@Test
	public void testSnapshotsSelectedDefinitionAcrossLaterRenameAndEdit() throws Exception {
		Path target = Files.createTempFile(null, ".txt");
		try {
			Files.writeString(target, "unsafe call");
			RegexCustomRuleDto rule = new RegexCustomRuleDto();
			rule.setId(42L);
			rule.setName("original");
			rule.setRegexPattern("unsafe");
			rule.setFileExtension(".txt");
			rule.setPriority(RulePriority.HIGH);
			RulesetDto selected = new RulesetDto();
			selected.setRules(Collections.singleton(rule));
			var identity = rule.getExecutionIdentity();
			CodeScanReport report = new RegexCallable(target, selected, new RegexBenchmarking()).call();
			Assertions.assertEquals(1, report.getViolations().size());
			rule.setName("renamed");
			rule.setRegexPattern("changed");
			Assertions.assertEquals(identity, report.getViolations().get(0).getRuleIdentity());
			Assertions.assertNotEquals(rule.getRevision(), identity.revision());
		} finally {
			Files.deleteIfExists(target);
		}
	}

	@Test
	public void testFindVio() throws Exception {
		// setup file
		Path target = Files.createTempFile(null, ".txt");
		String fileData = "Test String to search";
		Files.write(target, fileData.getBytes());
		// setup rule that always finds
		RegexCustomRuleDto rule = BDDMockito.mock(RegexCustomRuleDto.class);
		BDDMockito.given(rule.isValidExtension(BDDMockito.anyString())).willReturn(true);
		BDDMockito.given(rule.getPriority()).willReturn(RulePriority.HIGH);
		BDDMockito.given(ruleset.getAllRules()).willReturn(Collections.singleton(rule));
		BDDMockito.given(rule.getCompiledPattern()).willReturn(Pattern.compile(".*"));

		// do the test
		RegexCallable callable = new RegexCallable(target, ruleset, new RegexBenchmarking());
		CodeScanReport report = callable.call();
		Assertions.assertEquals(1, report.getViolations().size());
		Assertions.assertEquals(1, report.getViolations().get(0).getLineNum());
	}

	private static RegexCustomRuleDto textRule(String name, String pattern) {
		RegexCustomRuleDto rule = new RegexCustomRuleDto();
		rule.setId((long) name.hashCode());
		rule.setName(name);
		rule.setRegexPattern(pattern);
		rule.setFileExtension(".txt");
		rule.setPriority(RulePriority.HIGH);
		return rule;
	}

	@Test
	public void testCatastrophicPatternIsStoppedReportedOnceAndOtherRulesStillRun() throws Exception {
		Path target = Files.createTempFile(null, ".txt");
		try {
			// A backreference defeats the JDK's backtracking memoization, so this really does run
			// for far longer than the test is willing to wait (checked on JDK 21).
			String backtracking = "a".repeat(40);
			Files.writeString(target, backtracking + "\nfind me\n" + backtracking + "\n");
			RulesetDto selected = new RulesetDto();
			selected.setRules(new java.util.LinkedHashSet<>(java.util.List.of(
					textRule("Slow rule", "(a*)*\\1b"), textRule("Plain rule", "find me"))));

			CodeScanReport[] report = new CodeScanReport[1];
			Assertions.assertTimeoutPreemptively(java.time.Duration.ofSeconds(30),
					() -> report[0] = new RegexCallable(target, selected, new RegexBenchmarking(),
							java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(200)).call());

			Assertions.assertEquals(1, report[0].getViolations().size(), "only the plain rule matches");
			Assertions.assertEquals("Plain rule", report[0].getViolations().get(0).getViolationName());
			Assertions.assertEquals(1, report[0].getErrors().size(), "the slow rule is reported once, not per line");
			Assertions.assertTrue(report[0].getErrors().get(0).getErrorMessage().contains("Slow rule"));
		} finally {
			Files.deleteIfExists(target);
		}
	}

	@Test
	public void testOrdinaryPatternsAreNotAffectedByTheMatchTimeout() throws Exception {
		Path target = Files.createTempFile(null, ".txt");
		try {
			Files.writeString(target, "password = secret\nnothing here\n");
			RulesetDto selected = new RulesetDto();
			selected.setRules(Collections.singleton(textRule("Password", "password\\s*=")));

			CodeScanReport report = new RegexCallable(target, selected, new RegexBenchmarking()).call();

			Assertions.assertEquals(1, report.getViolations().size());
			Assertions.assertTrue(report.getErrors().isEmpty());
		} finally {
			Files.deleteIfExists(target);
		}
	}

	@Test
	public void testFindNoVio() throws Exception {
		// setup file
		Path target = Files.createTempFile(null, ".txt");
		String fileData = "Test String to search";
		Files.write(target, fileData.getBytes());

		// setup rule that never finds
		RegexCustomRuleDto rule = BDDMockito.mock(RegexCustomRuleDto.class);
		BDDMockito.given(rule.isValidExtension(BDDMockito.anyString())).willReturn(true);
		BDDMockito.given(ruleset.getAllRules()).willReturn(Collections.singleton(rule));
		BDDMockito.given(rule.getCompiledPattern()).willReturn(Pattern.compile("$^"));

		// do the test
		RegexCallable callable = new RegexCallable(target, ruleset, new RegexBenchmarking());
		CodeScanReport report = callable.call();
		Assertions.assertEquals(0, report.getViolations().size());
	}

	@Test
	public void testInvalidExt() throws Exception {
		// setup file
		Path target = Files.createTempFile(null, ".txt");
		String fileData = "Test String to search";
		Files.write(target, fileData.getBytes());

		// setup rule that won't match ext
		RegexCustomRuleDto rule = BDDMockito.mock(RegexCustomRuleDto.class);
		BDDMockito.given(rule.isValidExtension(BDDMockito.anyString())).willReturn(false);
		BDDMockito.given(ruleset.getAllRules()).willReturn(Collections.singleton(rule));

		// do the test
		RegexCallable callable = new RegexCallable(target, ruleset, new RegexBenchmarking());
		CodeScanReport report = callable.call();
		Assertions.assertEquals(0, report.getViolations().size());
	}

	@Test
	public void testException() throws Exception {
		// setup a file
		Path target = Files.createTempDirectory(null).resolve("foo.txt");
		// do the test
		RegexCallable callable = new RegexCallable(target, ruleset, new RegexBenchmarking());
		CodeScanReport report = callable.call();
		Assertions.assertEquals(0, report.getViolations().size());
		Assertions.assertEquals(1, report.getErrors().size());
	}

}
