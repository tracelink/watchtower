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
import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

@ExtendWith(MockitoExtension.class)
public class RegexCallableTest {

	@Mock
	RulesetDto ruleset;

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
		ScanReport report = callable.call();
		Assertions.assertEquals(1, report.getViolations().size());
		Assertions.assertEquals(1, report.getViolations().get(0).getLineNum());
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
		ScanReport report = callable.call();
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
		ScanReport report = callable.call();
		Assertions.assertEquals(0, report.getViolations().size());
	}

	@Test
	public void testException() throws Exception {
		// setup a file
		Path target = Files.createTempDirectory(null).resolve("foo.txt");
		// do the test
		RegexCallable callable = new RegexCallable(target, ruleset, new RegexBenchmarking());
		ScanReport report = callable.call();
		Assertions.assertEquals(0, report.getViolations().size());
		Assertions.assertEquals(1, report.getErrors().size());
	}

}
