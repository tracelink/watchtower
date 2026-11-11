package com.tracelink.appsec.module.regex.scanner;

import java.nio.file.Files;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.Callable;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import com.tracelink.appsec.module.regex.controller.RegexRuleEditControllerTest;
import com.tracelink.appsec.module.regex.model.RegexCustomRuleDto;
import com.tracelink.appsec.module.regex.model.RegexProvidedRuleDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.processor.MultiThreadedProcessor;
import com.tracelink.appsec.watchtower.core.scan.code.processor.SingleThreadedProcessor;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;

@ExtendWith(MockitoExtension.class)
public class RegexScannerTest {

	@Test
	public void testProcessorAndSupportedRuleContract() throws Exception {
		Assertions.assertEquals(SingleThreadedProcessor.class.getName(),
				new RegexScanner().getProcessor(0, null).getClass().getName());

		Assertions.assertEquals(MultiThreadedProcessor.class.getName(),
				new RegexScanner().getProcessor(1, null).getClass().getName());
		Callable<CodeScanReport> callable = new RegexScanner().getCreator(null)
				.createCallable(java.nio.file.Path.of("sample.txt"), null);
		Assertions.assertEquals(RegexCallable.class, callable.getClass());
		Assertions.assertEquals(Arrays.asList(RegexCustomRuleDto.class, RegexProvidedRuleDto.class),
				new RegexScanner().getSupportedRuleClass());
	}

	@Test
	public void testScanEvidenceAndProcessorFailures() throws Exception {
		RulesetDto ruleset = new RulesetDto();
		RegexCustomRuleDto rule = RegexRuleEditControllerTest.getRegexRuleDto();
		rule.setId(100L);
		ruleset.setRules(Collections.singleton(rule));
		CodeScanConfig config = new CodeScanConfig();
		config.setRuleset(ruleset);
		config.setBenchmarkEnabled(true);
		config.setWorkingDirectory(Files.createTempDirectory(null));
		CodeScanReport report = new RegexScanner().scan(config);
		Assertions.assertNotNull(report);
		Assertions.assertEquals(0, report.getErrors().size());
		Assertions.assertEquals(0, report.getViolations().size());
		RegexScanner scanner = new RegexScanner();
		var identity = scanner.getExecutionIdentity(config);
		Assertions.assertTrue(identity.isReusable());
		var snapshot = com.tracelink.appsec.watchtower.core.scan.code.CodeScanExecutionSnapshot
				.capture(ruleset, java.util.List.of(scanner), config).withOutcome(scanner, "RAN");
		Assertions.assertTrue(snapshot.isReusable());
		Assertions.assertTrue(snapshot.hasSuccessfulExecution());
		config.setWorkingDirectory(Files.createTempDirectory(null));
		config.setBenchmarkEnabled(false);
		Assertions.assertEquals(identity, scanner.getExecutionIdentity(config));
		config.setThreads(config.getThreads() + 1);
		Assertions.assertNotEquals(identity, scanner.getExecutionIdentity(config));
		Assertions.assertFalse(new RegexScanner() {}.getExecutionIdentity(config).isReusable());
		// Processor failures must survive into the report so a failed scan cannot be reused.
		config.setWorkingDirectory(config.getWorkingDirectory().resolve("missing"));
		Assertions.assertFalse(scanner.scan(config).getErrors().isEmpty());
	}
}
