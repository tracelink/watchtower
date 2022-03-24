package com.tracelink.appsec.module.regex.scanner;

import java.nio.file.Files;
import java.util.Collections;
import java.util.concurrent.Callable;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import com.tracelink.appsec.module.regex.controller.RegexRuleEditControllerTest;
import com.tracelink.appsec.module.regex.model.RegexCustomRuleDto;
import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.processor.MultiThreadedProcessor;
import com.tracelink.appsec.watchtower.core.scan.processor.SingleThreadedProcessor;

@ExtendWith(MockitoExtension.class)
public class RegexScannerTest {

	@Test
	public void testProcessorCreation() {
		Assertions.assertEquals(SingleThreadedProcessor.class.getName(),
				new RegexScanner().getProcessor(0, null).getClass().getName());

		Assertions.assertEquals(MultiThreadedProcessor.class.getName(),
				new RegexScanner().getProcessor(1, null).getClass().getName());
	}

	@Test
	public void testSentinelScanWithBenchmarking() throws Exception {
		RulesetDto ruleset = new RulesetDto();
		RegexCustomRuleDto rule = RegexRuleEditControllerTest.getRegexRuleDto();
		ruleset.setRules(Collections.singleton(rule));
		CodeScanConfig config = new CodeScanConfig();
		config.setRuleset(ruleset);
		config.setBenchmarkEnabled(true);
		config.setWorkingDirectory(Files.createTempDirectory(null));
		ScanReport report = new RegexScanner().scan(config);
		Assertions.assertNotNull(report);
		Assertions.assertEquals(0, report.getErrors().size());
		Assertions.assertEquals(0, report.getViolations().size());
	}

	@Test
	public void testGetCreator() throws Exception {
		Callable<ScanReport> c = new RegexScanner().getCreator(null)
				.createCallable(Files.createTempFile(null, null), null);
		Assertions.assertEquals(RegexCallable.class.getName(), c.getClass().getName());
	}

	@Test
	public void testSupportedRules() {
		Assertions.assertEquals(RegexCustomRuleDto.class,
				new RegexScanner().getSupportedRuleClass());
	}
}
