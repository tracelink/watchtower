package com.tracelink.appsec.module.json.scanner;

import java.nio.file.Files;
import java.util.Collections;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.json.model.JsonRuleDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;

public class JsonScannerTest {

	@Test
	public void testScan() throws Exception {
		RulesetDto ruleset = new RulesetDto();
		JsonRuleDto rule = new JsonRuleDto();
		rule.setId(101L);
		rule.setName("flag");
		rule.setQuery("$.flag");
		rule.setFileExtension(".json");
		rule.setPriority(com.tracelink.appsec.watchtower.core.rule.RulePriority.HIGH);
		ruleset.setRules(Collections.singleton(rule));
		CodeScanConfig config = new CodeScanConfig();
		config.setRuleset(ruleset);
		config.setBenchmarkEnabled(true);
		config.setWorkingDirectory(Files.createTempDirectory(null));
		CodeScanReport report = new JsonScanner().scan(config);
		Assertions.assertNotNull(report);
		Assertions.assertEquals(0, report.getErrors().size());
		Assertions.assertEquals(0, report.getViolations().size());
		Assertions.assertEquals(Collections.singletonList(JsonRuleDto.class),
				new JsonScanner().getSupportedRuleClass());
		JsonScanner scanner = new JsonScanner();
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
		Assertions.assertFalse(new JsonScanner() {}.getExecutionIdentity(config).isReusable());
		Files.writeString(config.getWorkingDirectory().resolve("sample.json"), "{\"flag\":true}");
		var findings = scanner.scan(config);
		Assertions.assertTrue(findings.getErrors().isEmpty());
		Assertions.assertEquals(1, findings.getViolations().size());
		Assertions.assertEquals(rule.getExecutionIdentity(), findings.getViolations().getFirst().getRuleIdentity());
	}

	@Test
	public void brokenFilesAreReportedWithoutHidingFindingsInTheOthers() throws Exception {
		RulesetDto ruleset = new RulesetDto();
		JsonRuleDto rule = new JsonRuleDto();
		rule.setId(102L);
		rule.setName("age");
		rule.setQuery("$.people.*.[?(@.age>45)]");
		rule.setFileExtension("");
		rule.setPriority(com.tracelink.appsec.watchtower.core.rule.RulePriority.HIGH);
		ruleset.setRules(Collections.singleton(rule));
		CodeScanConfig config = new CodeScanConfig();
		config.setRuleset(ruleset);
		config.setThreads(0); // as a repository scan runs
		config.setWorkingDirectory(Files.createTempDirectory(null));
		var tree = config.getWorkingDirectory();
		Files.createDirectories(tree.resolve("json"));
		Files.createDirectories(tree.resolve("json-fault"));
		Files.writeString(tree.resolve("json/match.json"),
				"{\"people\":[{\"name\":\"Ada\",\"age\":50},{\"name\":\"Bo\",\"age\":30}]}\n");
		Files.writeString(tree.resolve("json/match.yaml"), "people:\n  - name: Ada\n    age: 50\n");
		Files.writeString(tree.resolve("json-fault/malformed.json"),
				"{\"people\":[{\"name\":\"Ada\",\"age\":50},\n");
		Files.writeString(tree.resolve("json-fault/malformed.yaml"), "people: [unclosed\n  - : :\n");

		CodeScanReport report = new JsonScanner().scan(config);

		Assertions.assertEquals(2, report.getViolations().size(),
				"findings of the valid files must survive");
		Assertions.assertEquals(2, report.getErrors().size(), "one error per broken file");
	}
}
