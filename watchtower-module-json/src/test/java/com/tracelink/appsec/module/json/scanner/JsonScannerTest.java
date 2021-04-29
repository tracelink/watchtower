package com.tracelink.appsec.module.json.scanner;

import java.nio.file.Files;
import java.util.Collections;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.json.model.JsonRuleDto;
import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.ScanConfig;

public class JsonScannerTest {

	@Test
	public void testScan() throws Exception {
		RulesetDto ruleset = new RulesetDto();
		JsonRuleDto rule = new JsonRuleDto();
		ruleset.setRules(Collections.singleton(rule));
		ScanConfig config = new ScanConfig();
		config.setRuleset(ruleset);
		config.setBenchmarkEnabled(true);
		config.setWorkingDirectory(Files.createTempDirectory(null));
		ScanReport report = new JsonScanner().scan(config);
		Assertions.assertNotNull(report);
		Assertions.assertEquals(0, report.getErrors().size());
		Assertions.assertEquals(0, report.getViolations().size());
	}

	@Test
	public void testSupportedRules() {
		Assertions.assertEquals(JsonRuleDto.class, new JsonScanner().getSupportedRuleClass());
	}
}
