package com.tracelink.appsec.module.checkov.scanner;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.mockito.Mock;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.module.checkov.engine.CheckovEngine;
import com.tracelink.appsec.module.checkov.model.CheckovRuleDto;
import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.ScanConfig;

@ExtendWith(SpringExtension.class)
public class CheckovScannerTest {

	@Mock
	private CheckovEngine engine;

	@Test
	public void testScanException() {
		CheckovScanner scanner = new CheckovScanner(engine);
		ScanReport report = scanner.scan(new ScanConfig());
		MatcherAssert.assertThat(report.getErrors(), Matchers.hasSize(1));
		MatcherAssert.assertThat(report.getErrors().get(0).getErrorMessage(),
				Matchers.containsString("Error while scanning"));
	}

	@Test
	public void testMissingRules() throws Exception {
		Map<String, CheckovRuleDto> coreRules = new HashMap<>();
		coreRules.put("FOOBAR", new CheckovRuleDto());
		BDDMockito.when(engine.getCoreRules()).thenReturn(coreRules);

		CheckovRuleDto rule = new CheckovRuleDto();
		rule.setName("NOTFOOBAR");
		rule.setPriority(RulePriority.HIGH);
		rule.setCoreRule(true);

		RulesetDto ruleset = new RulesetDto();
		ruleset.setRules(new HashSet<>(Arrays.asList(rule)));

		ScanConfig config = new ScanConfig();
		config.setRuleset(ruleset);

		CheckovScanner scanner = new CheckovScanner(engine);
		scanner.scan(config);
		ArgumentCaptor<List<CheckovRuleDto>> listCaptor =
				ArgumentCaptor.forClass(List.class);
		BDDMockito.verify(engine).runCheckovDirectoryScan(BDDMockito.any(), listCaptor.capture());
		MatcherAssert.assertThat(listCaptor.getValue(), Matchers.hasSize(0));
	}
}
