package com.tracelink.appsec.module.json.scanner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.json.model.JsonRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;

public class JsonCallableTest {
	private final String code = "{\n" +
			"  \"type\": \"person\",\n" +
			"  \"people\": [\n" +
			"    {\n" +
			"      \"name\": \"Fred\",\n" +
			"      \"age\": 23\n" +
			"    },\n" +
			"    {\n" +
			"      \"name\": \"Alex\",\n" +
			"      \"age\": 53\n" +
			"    },\n" +
			"    {\n" +
			"      \"name\": \"James\",\n" +
			"      \"age\": 39\n" +
			"    }\n" +
			"  ]\n" +
			"}";

	private final String query = "$.people.*.[?(@.age>45)]";


	@Test
	public void testCall() throws Exception {
		JsonRuleDto rule = new JsonRuleDto();
		rule.setName("test");
		rule.setId(42L);
		rule.setQuery(query);
		rule.setPriority(RulePriority.HIGH);
		rule.setFileExtension("");
		RulesetDto ruleset = new RulesetDto();
		ruleset.setRules(Collections.singleton(rule));
		Path temp = Files.createTempFile(null, null);
		Files.write(temp, code.getBytes());

		JsonCallable call = new JsonCallable(temp, ruleset);
		CodeScanReport report = call.call();
		MatcherAssert.assertThat(report.getViolations(), Matchers.hasSize(1));
		MatcherAssert.assertThat(report.getViolations().get(0).getLineNum(), Matchers.is(8));
		Assertions.assertEquals(rule.getExecutionIdentity(),
				report.getViolations().get(0).getRuleIdentity());
		Files.delete(temp);
		// Equal scalars must preserve occurrence locations rather than share cached nodes.
		CodeScanReport duplicates = scan(".json", "{\"values\":[\n1,\n1,\ntrue,\ntrue,\nnull,\nnull,\n\"x\",\n\"x\"\n]}", "$.values[*]");
		Assertions.assertEquals(java.util.List.of(2,3,4,5,6,7,8,9), duplicates.getViolations().stream().map(v -> v.getLineNum()).toList());
		String yaml = "apiVersion: v1\nkind: Pod\nspec:\n  securityContext:\n    privileged: true\n---\ndefaults: &defaults\n  privileged: true\nspec:\n  securityContext:\n    <<: *defaults\n---\nspec:\n  containers:\n    - securityContext:\n        privileged: true\n    - securityContext:\n        privileged: true\n";
		for (String extension : java.util.List.of(".yaml", ".yml")) {
			CodeScanReport documents = scan(extension, yaml, "$..securityContext.privileged");
			Assertions.assertTrue(documents.getErrors().isEmpty());
			Assertions.assertEquals(java.util.List.of(5,11,16,18), documents.getViolations().stream().map(v -> v.getLineNum()).toList());
			Assertions.assertEquals(java.util.List.of("YAML document 1: ","YAML document 2: ","YAML document 3: ","YAML document 3: "), documents.getViolations().stream().map(v -> v.getMessage()).toList());
		}
		CodeScanReport overrides = scan(".yml", "base: &base {privileged: true}\nspec:\n  securityContext:\n    privileged: false\n    <<: *base\n", "$..securityContext[?(@.privileged == true)]");
		Assertions.assertTrue(overrides.getViolations().isEmpty());
	}

	@Test
	public void testUnparseableFile() throws Exception {
		JsonRuleDto rule = new JsonRuleDto();
		rule.setName("test");
		rule.setQuery(query);
		rule.setPriority(RulePriority.HIGH);
		rule.setFileExtension("");
		RulesetDto ruleset = new RulesetDto();
		ruleset.setRules(Collections.singleton(rule));
		Path temp = Files.createTempFile(null, null);
		Files.write(temp, "}{".getBytes());

		JsonCallable call = new JsonCallable(temp, ruleset);
		CodeScanReport report = call.call();
		MatcherAssert.assertThat(report.getErrors(), Matchers.hasSize(1));
		MatcherAssert.assertThat(report.getErrors().get(0).getErrorMessage(),
				Matchers.containsString("Could not parse"));
		Files.delete(temp);
		for (String invalid : java.util.List.of("a: [", "a: 1\na: 2", "a: !!java/object:java.lang.Runtime {}", "a: &a [*a]", "a: *missing", "a: .inf", "a: &same 1\nb: &same 2", "a: !!binary Zm9v")) {
			Assertions.assertFalse(scan(".yaml", invalid, "$..a").getErrors().isEmpty(), invalid);
		}
		Assertions.assertFalse(scan(".yaml", "a: ".repeat(70) + "1", "$..a").getErrors().isEmpty());
		Assertions.assertFalse(scan(".yaml", "a: &a [1]\n" + java.util.stream.IntStream.range(0,51).mapToObj(i -> "b"+i+": *a\n").collect(java.util.stream.Collectors.joining()), "$..a").getErrors().isEmpty());
		Assertions.assertFalse(scan(".yaml", "a: " + "x".repeat(2*1024*1024), "$..a").getErrors().isEmpty());
	}
	private CodeScanReport scan(String suffix, String text, String query) throws Exception {
		JsonRuleDto rule = new JsonRuleDto(); rule.setName("yaml fixture"); rule.setQuery(query); rule.setFileExtension(suffix); rule.setPriority(RulePriority.HIGH);
		RulesetDto ruleset = new RulesetDto(); ruleset.setRules(Collections.singleton(rule));
		Path file = Files.createTempFile("configuration-", suffix);
		try { Files.writeString(file, text); return new JsonCallable(file, ruleset).call(); }
		finally { Files.deleteIfExists(file); }
	}
}
