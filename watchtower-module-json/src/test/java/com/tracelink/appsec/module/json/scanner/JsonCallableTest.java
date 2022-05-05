package com.tracelink.appsec.module.json.scanner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
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
	}

	@Test
	public void testUnparseableFile() throws IOException {
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
	}
}
