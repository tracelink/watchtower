package com.tracelink.appsec.module.eslint.scanner;

import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.module.eslint.engine.LinterEngine;
import com.tracelink.appsec.module.eslint.model.EsLintCustomRuleDto;
import com.tracelink.appsec.module.eslint.model.EsLintRuleDtoTest;
import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.scm.ScmScanConfig;

@ExtendWith(SpringExtension.class)
public class EsLintScannerTest {

	private static LinterEngine engine;

	private EsLintScanner scanner;
	private RulesetDto rulesetDto;

	@BeforeAll
	public static void init() {
		engine = new LinterEngine();
	}

	@BeforeEach
	public void setup() throws Exception {
		scanner = new EsLintScanner(engine);
		rulesetDto = new RulesetDto();
		rulesetDto.setName("ESLint rules");
		rulesetDto.setDescription("A collection of custom and core ESLint rules");
		rulesetDto.setRules(new HashSet<>(Arrays.asList(engine.getCoreRules().get("no-console"),
				engine.getCoreRules().get("no-eval"), EsLintRuleDtoTest.getCustomEsLintRule())));

	}

	@Test
	public void testScan() throws Exception {
		ScmScanConfig config = new ScmScanConfig();
		config.setWorkingDirectory(
				Paths.get(getClass().getClassLoader().getResource("scan/simple.js").toURI()));
		config.setRuleset(rulesetDto);
		ScanReport report = scanner.scan(config);
		Assertions.assertTrue(report.getErrors().isEmpty());
		Assertions.assertEquals(2, report.getViolations().size());
		Assertions.assertTrue(report.getViolations().stream()
				.anyMatch(v -> v.getViolationName().equals("no-console") && v.getMessage()
						.equals("Unexpected console statement.") && v.getLineNum() == 2));
		Assertions.assertTrue(report.getViolations().stream()
				.anyMatch(v -> v.getViolationName().equals("no-eval") && v.getMessage()
						.equals("eval can be harmful.") && v.getLineNum() == 3));
	}

	@Test
	public void testScanSingleThread() throws Exception {
		ScmScanConfig config = new ScmScanConfig();
		config.setThreads(0);
		config.setWorkingDirectory(
				Paths.get(getClass().getClassLoader().getResource("scan/simple.js").toURI()));
		config.setRuleset(rulesetDto);
		ScanReport report = scanner.scan(config);
		Assertions.assertTrue(report.getErrors().isEmpty());
		Assertions.assertEquals(2, report.getViolations().size());
		Assertions.assertTrue(report.getViolations().stream()
				.anyMatch(v -> v.getViolationName().equals("no-console") && v.getMessage()
						.equals("Unexpected console statement.") && v.getLineNum() == 2));
		Assertions.assertTrue(report.getViolations().stream()
				.anyMatch(v -> v.getViolationName().equals("no-eval") && v.getMessage()
						.equals("eval can be harmful.") && v.getLineNum() == 3));
	}

	@Test
	public void testScanCannotExportRuleset() {
		rulesetDto.setName(null);
		ScmScanConfig config = new ScmScanConfig();
		config.setRuleset(rulesetDto);
		ScanReport report = scanner.scan(config);
		Assertions.assertEquals(1, report.getErrors().size());
		Assertions.assertTrue(report.getErrors().get(0).getErrorMessage()
				.contains("Exception writing ESLint ruleset to file: "));
	}

	@Test
	public void testScanFatalError() throws Exception {
		ScmScanConfig config = new ScmScanConfig();
		config.setThreads(0);
		config.setWorkingDirectory(
				Paths.get(getClass().getClassLoader().getResource("scan/invalid.js").toURI()));
		config.setRuleset(rulesetDto);
		ScanReport report = scanner.scan(config);
		Assertions.assertEquals(1, report.getErrors().size());
		Assertions.assertEquals("Parsing error: Unterminated string constant",
				report.getErrors().get(0).getErrorMessage());
	}

	@Test
	public void testScanError() throws Exception {
		ScmScanConfig config = new ScmScanConfig();
		config.setThreads(0);
		config.setWorkingDirectory(
				Paths.get(getClass().getClassLoader().getResource("scan/simple.js").toURI()));

		EsLintCustomRuleDto rule = new EsLintCustomRuleDto();
		String createFunction = "create(context) {\n"
				+ "    return {\n"
				+ "        VariableDeclaration(node) {\n"
				+ "            context.report({ node, messageId: \"unexpected\" });\n"
				+ "        }\n"
				+ "    };\n"
				+ "}";
		rule.setName("rule");
		rule.setMessage("message");
		rule.setExternalUrl("url");
		rule.setPriority(RulePriority.LOW);
		rule.setCreateFunction(createFunction);
		RulesetDto ruleset = new RulesetDto();
		ruleset.setName("ruleset");
		ruleset.setDescription("description");
		ruleset.setRules(Collections.singleton(rule));

		config.setRuleset(ruleset);
		ScanReport report = scanner.scan(config);
		Assertions.assertEquals(1, report.getErrors().size());
		Assertions.assertTrue(
				report.getErrors().get(0).getErrorMessage().contains(
						"TypeError: context.report() called with a messageId, but no messages were present in the rule metadata."));
	}

	@Test
	public void testGetSupportedRuleClass() {
		Assertions.assertEquals(EsLintCustomRuleDto.class, scanner.getSupportedRuleClass());
	}
}
