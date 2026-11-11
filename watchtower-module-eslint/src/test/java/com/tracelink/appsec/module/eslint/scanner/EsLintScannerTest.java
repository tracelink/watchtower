package com.tracelink.appsec.module.eslint.scanner;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.module.eslint.engine.LinterEngine;
import com.tracelink.appsec.module.eslint.model.EsLintCustomRuleDto;
import com.tracelink.appsec.module.eslint.model.EsLintProvidedRuleDto;
import com.tracelink.appsec.module.eslint.model.EsLintRuleDtoTest;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;

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
	public void testScan(@org.junit.jupiter.api.io.TempDir Path temporary) throws Exception {
		Assertions.assertEquals(Arrays.asList(EsLintCustomRuleDto.class, EsLintProvidedRuleDto.class),
				scanner.getSupportedRuleClass());
		var parsed = engine.parseAst("const value = \"\\\\a雪\";\n");
		Assertions.assertFalse(parsed.hasErrors());
		var literal = com.google.gson.JsonParser.parseString(parsed.getResults()).getAsJsonObject()
				.getAsJsonArray("body").get(0).getAsJsonObject().getAsJsonArray("declarations")
				.get(0).getAsJsonObject().getAsJsonObject("init");
		Assertions.assertEquals("\\a雪", literal.get("value").getAsString(),
				"Source arguments must preserve backslashes and Unicode");
		Assertions.assertEquals("\"\\\\a雪\"", literal.get("raw").getAsString());
		CodeScanConfig config = new CodeScanConfig();
		config.setWorkingDirectory(
				Paths.get(getClass().getClassLoader().getResource("scan/simple.js").toURI()));
		config.setRuleset(rulesetDto);
		Assertions.assertFalse(scanner.getExecutionIdentity(config).isReusable(),
				"Arbitrary custom JavaScript has untracked external inputs");
		for (int threads : List.of(0, 1)) {
			config.setThreads(threads);
			CodeScanReport report = scanner.scan(config);
			Assertions.assertTrue(report.getErrors().isEmpty());
			Assertions.assertEquals(2, report.getViolations().size());
			report.getViolations().forEach(violation -> {
				var selected = rulesetDto.getAllRules().stream()
						.filter(rule -> rule.getName().equals(violation.getViolationName())).findFirst().orElseThrow();
				Assertions.assertEquals(selected.getExecutionIdentity(), violation.getRuleIdentity());
			});
			Assertions.assertTrue(report.getViolations().stream()
					.anyMatch(v -> v.getViolationName().equals("no-console") && v.getMessage()
							.equals("Unexpected console statement.") && v.getLineNum() == 2));
			Assertions.assertTrue(report.getViolations().stream()
					.anyMatch(v -> v.getViolationName().equals("no-eval") && v.getMessage()
							.equals("eval can be harmful.") && v.getLineNum() == 3));
		}
		var console = engine.getCoreRules().get("no-console");
		console.setId(41L);
		var eval = engine.getCoreRules().get("no-eval");
		eval.setId(42L);
		rulesetDto.setRules(Set.of(console, eval));
		var identity = scanner.getExecutionIdentity(config);
		Assertions.assertTrue(identity.isReusable(), "Provided rules must establish complete runtime evidence");
		var captured = com.tracelink.appsec.watchtower.core.scan.code.CodeScanExecutionSnapshot
				.capture(rulesetDto, List.of(scanner), config).withOutcome(scanner, "RAN");
		Assertions.assertTrue(captured.hasSuccessfulExecution());
		Assertions.assertTrue(scanner.scan(config).getErrors().isEmpty());
		config.setBenchmarkEnabled(true);
		config.setWorkingDirectory(temporary.resolve("other"));
		rulesetDto.setDescription("Documentation changes do not affect detection");
		Assertions.assertEquals(identity, scanner.getExecutionIdentity(config));
		config.setThreads(2);
		Assertions.assertNotEquals(identity, scanner.getExecutionIdentity(config));
		Assertions.assertFalse(new EsLintScanner(engine) {}.getExecutionIdentity(config).isReusable());
		rulesetDto.setDescription("unfinished\\");
		Assertions.assertFalse(scanner.getExecutionIdentity(config).isReusable(),
				"Malformed exported configuration must not qualify for reuse");
		rulesetDto.setDescription("Valid configuration");
		var script = Paths.get("eslint_work", "linter_scan.js");
		byte[] originalScript = Files.readAllBytes(script);
		try {
			Files.writeString(script, "changed runtime bridge");
			Assertions.assertFalse(scanner.getExecutionIdentity(config).isReusable());
		} finally {
			Files.write(script, originalScript);
		}
		var missing = new EsLintProvidedRuleDto();
		missing.setName("missing-engine-rule");
		missing.setPriority(RulePriority.LOW);
		rulesetDto.setRules(Set.of(missing));
		Assertions.assertFalse(scanner.getExecutionIdentity(config).isReusable());
		Assertions.assertFalse(new com.google.gson.Gson().toJson(identity).contains(temporary.toString()));
		assertPackageEvidence(temporary);
	}

	@Test
	public void testScanCannotExportRuleset() {
		rulesetDto.setName(null);
		CodeScanConfig config = new CodeScanConfig();
		config.setRuleset(rulesetDto);
		CodeScanReport report = scanner.scan(config);
		Assertions.assertEquals(1, report.getErrors().size());
		Assertions.assertTrue(report.getErrors().get(0).getErrorMessage()
				.contains("Exception writing ESLint ruleset to file: "));
	}

	@Test
	public void testScanFatalError() throws Exception {
		CodeScanConfig config = new CodeScanConfig();
		config.setThreads(0);
		config.setWorkingDirectory(
				Paths.get(getClass().getClassLoader().getResource("scan/invalid.js").toURI()));
		config.setRuleset(rulesetDto);
		CodeScanReport report = scanner.scan(config);
		Assertions.assertEquals(1, report.getErrors().size());
		Assertions.assertEquals("Parsing error: Unterminated string constant",
				report.getErrors().get(0).getErrorMessage());
	}

	@Test
	public void testScanError() throws Exception {
		CodeScanConfig config = new CodeScanConfig();
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
		CodeScanReport report = scanner.scan(config);
		Assertions.assertEquals(1, report.getErrors().size());
		Assertions.assertTrue(
				report.getErrors().get(0).getErrorMessage().contains(
						"TypeError: context.report() called with a messageId, but no messages were present in the rule metadata."));
		rule.setCreateFunction("create(context) { process.exit(7); }");
		report = scanner.scan(config);
		Assertions.assertEquals(1, report.getErrors().size(),
				"A nonzero exit with empty stdout/stderr must be reported as a failure");
		Assertions.assertTrue(report.getErrors().getFirst().getErrorMessage().contains("exit=7"));
	}

	private void assertPackageEvidence(Path temporary) throws Exception {
		Path helper = Paths.get(getClass().getClassLoader().getResource("js/linter_identity.js").toURI());
		Path artifact = Files.createDirectory(temporary.resolve("package")).toRealPath();
		Files.writeString(artifact.resolve("package.json"), "{\"name\":\"fixture\",\"version\":\"1.0.0\"}");
		Files.writeString(artifact.resolve("index.js"), "first implementation");
		String original = packageHash(helper, artifact);
		Files.writeString(artifact.resolve(".npmrc"), "credentials: private-marker");
		Assertions.assertEquals(original, packageHash(helper, artifact), "npm credentials are excluded");
		Files.writeString(artifact.resolve("index.js"), "changed implementation");
		Assertions.assertNotEquals(original, packageHash(helper, artifact));
		Files.writeString(artifact.resolve("data.json"), "{\"parser\":true}");
		String withData = packageHash(helper, artifact);
		Files.writeString(artifact.resolve("data.json"), "{\"parser\":false}");
		Assertions.assertNotEquals(withData, packageHash(helper, artifact));
		var override = new com.tracelink.appsec.watchtower.core.process.ProcessRunner().run(
				new com.tracelink.appsec.watchtower.core.process.ProcessRequest(List.of("node", "-p",
						"process.env.NODE_PATH=process.argv[2];require(process.argv[1]).capture('')",
						helper.toString(), temporary.resolve("private-marker").toString()),
						temporary, Duration.ofSeconds(15), 1024));
		Assertions.assertTrue(override.isSuccess());
		Assertions.assertTrue(override.stdout().contains("\"complete\":false"));
		Assertions.assertFalse(override.stdout().contains("private-marker"));
	}

	private String packageHash(Path helper, Path artifact) {
		var result = new com.tracelink.appsec.watchtower.core.process.ProcessRunner().run(
				new com.tracelink.appsec.watchtower.core.process.ProcessRequest(List.of("node", "-p",
						"require(process.argv[1]).hashPackage(process.argv[2])", helper.toString(), artifact.toString()),
						artifact, Duration.ofSeconds(15), 1024));
		Assertions.assertTrue(result.isSuccess());
		Assertions.assertTrue(result.stdout().trim().matches("[0-9a-f]{64}"));
		return result.stdout().trim();
	}
}
