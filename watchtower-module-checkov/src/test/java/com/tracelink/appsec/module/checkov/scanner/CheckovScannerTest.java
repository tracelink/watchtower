package com.tracelink.appsec.module.checkov.scanner;

import java.nio.file.Path;
import java.util.Set;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.google.gson.JsonParser;
import com.tracelink.appsec.module.checkov.engine.CheckovEngine;
import com.tracelink.appsec.module.checkov.model.CheckovProvidedRuleDto;
import com.tracelink.appsec.watchtower.core.module.scanner.ScanScope;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;

@ExtendWith({SpringExtension.class, MockitoExtension.class})
@MockitoSettings(strictness = Strictness.LENIENT)
public class CheckovScannerTest {

	@Mock
	private CheckovEngine engine;

	@Test
	public void testFindingIdentityComesFromSelectedRules() throws Exception {
		var scanner = new CheckovScanner(engine);
		Assertions.assertEquals(ScanScope.MANIFEST_FILES, scanner.getRequiredScope());
		MatcherAssert.assertThat(scanner.getRequiredFilePatterns(),
				Matchers.containsInAnyOrder("**/*.tf", "**/*.yaml", "**/*.yml", "**/*.json"));
		Assertions.assertEquals(java.util.List.of(CheckovProvidedRuleDto.class), scanner.getSupportedRuleClass());
		var rule = new CheckovProvidedRuleDto();
		rule.setId(42L);
		rule.setName("CKV_TEST_1");
		rule.setPriority(RulePriority.HIGH);
		var ruleset = new RulesetDto();
		ruleset.setRules(Set.of(rule));
		CodeScanConfig config = new CodeScanConfig();
		config.setRuleset(ruleset);
		config.setWorkingDirectory(Path.of("/work"));
		var result = JsonParser.parseString("""
				{"results":{"failed_checks":[{"check_id":"CKV_TEST_1",
				"file_path":"/main.tf","file_line_range":[3,4]}]}}
				""").getAsJsonObject();
		Mockito.when(engine.runCheckovDirectoryScan(ArgumentMatchers.any(),
				ArgumentMatchers.any())).thenReturn(result);
		CodeScanReport report = scanner.scan(config);
		Assertions.assertTrue(report.getErrors().isEmpty());
		Assertions.assertEquals(1, report.getViolations().size());
		Assertions.assertEquals(rule.getExecutionIdentity(), report.getViolations().get(0).getRuleIdentity());
		result.addProperty("errors", "Checkov reported parsing errors");
		report = scanner.scan(config);
		Assertions.assertEquals(1, report.getErrors().size());
		Assertions.assertEquals(1, report.getViolations().size(), "Partial findings must retain failure evidence");
	}

	@Test
	public void testCheckovOwnSecretsChecksAreDroppedWithoutFailingTheScanner() {
		CheckovScanner scanner = new CheckovScanner(engine);
		var rule = new CheckovProvidedRuleDto();
		rule.setId(42L);
		rule.setName("CKV_TEST_1");
		rule.setPriority(RulePriority.HIGH);
		var ruleset = new RulesetDto();
		ruleset.setRules(Set.of(rule));
		CodeScanConfig config = new CodeScanConfig();
		config.setRuleset(ruleset);
		config.setWorkingDirectory(Path.of("/work"));
		var result = JsonParser.parseString("""
				{"results":{"failed_checks":[
				{"check_id":"CKV_SECRET_6","file_path":"/a.tf","file_line_range":[1,1]},
				{"check_id":"CKV_UNKNOWN_9","file_path":"/a.tf","file_line_range":[2,2]}]}}
				""").getAsJsonObject();
		Mockito.when(engine.runCheckovDirectoryScan(ArgumentMatchers.any(),
				ArgumentMatchers.any())).thenReturn(result);

		CodeScanReport report = scanner.scan(config);

		Assertions.assertEquals(0, report.getViolations().size());
		MatcherAssert.assertThat(report.getErrors(), Matchers.hasSize(1));
		MatcherAssert.assertThat(report.getErrors().get(0).getErrorMessage(),
				Matchers.containsString("CKV_UNKNOWN_9"));
	}

	@Test
	public void testScanException() {
		CheckovScanner scanner = new CheckovScanner(engine);
		CodeScanReport report = scanner.scan(new CodeScanConfig());
		MatcherAssert.assertThat(report.getErrors(), Matchers.hasSize(1));
		MatcherAssert.assertThat(report.getErrors().get(0).getErrorMessage(),
				Matchers.containsString("Error while scanning"));
	}

}
