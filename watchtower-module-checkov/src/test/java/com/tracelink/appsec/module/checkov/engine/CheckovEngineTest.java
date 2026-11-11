package com.tracelink.appsec.module.checkov.engine;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.io.FileUtils;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import com.tracelink.appsec.module.checkov.model.CheckovProvidedRuleDto;
import com.tracelink.appsec.module.checkov.scanner.CheckovScanner;
import com.tracelink.appsec.watchtower.core.process.ProcessRequest;
import com.tracelink.appsec.watchtower.core.process.ProcessResult;
import com.tracelink.appsec.watchtower.core.process.ProcessRunner;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanExecutionSnapshot;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;

public class CheckovEngineTest {

	@Test
	public void testCheckovEngineSetup(@TempDir Path temporary) throws Exception {
		assertResultProtocol(temporary);
		Path targetDirectory = null;
		try {
			targetDirectory = Files.createTempDirectory(null);
			try (InputStream is =
					this.getClass()
							.getResourceAsStream("/terraformtest/terraform_iam.tf")) {
				Files.copy(is, targetDirectory.resolve("terraform_test.tf"));
			}
			CheckovEngine engine = new CheckovEngine();
			MatcherAssert.assertThat(engine.getCoreRules(),
					Matchers.hasSize(Matchers.greaterThan(0)));
			var selected = engine.getCoreRules().stream().filter(r -> r.getName().equals("CKV_AWS_62"))
					.findFirst().orElseThrow();
			selected.setId(42L);
			var ruleset = new RulesetDto();
			ruleset.setRules(Set.of(selected));
			var config = new CodeScanConfig();
			config.setRuleset(ruleset);
			config.setWorkingDirectory(targetDirectory);
			var scanner = new CheckovScanner(engine);
			var evidence = scanner.getExecutionIdentity(config);
			Assertions.assertNotNull(evidence.version(), "The installed version/catalog must be captured");
			Assertions.assertTrue(evidence.version().contains("/checkov:2.0.257/"));
			Assertions.assertFalse(evidence.isReusable(), "Python/external inputs are not yet certified");
			Assertions.assertFalse(CodeScanExecutionSnapshot.capture(ruleset, List.of(scanner), config)
					.withOutcome(scanner, "RAN").hasSuccessfulExecution());
			config.setBenchmarkEnabled(true);
			config.setWorkingDirectory(temporary.resolve("private-marker"));
			Assertions.assertEquals(evidence, scanner.getExecutionIdentity(config));
			config.setThreads(2);
			Assertions.assertNotEquals(evidence, scanner.getExecutionIdentity(config));
			Assertions.assertFalse(new com.google.gson.Gson().toJson(evidence).contains("private-marker"));
			Assertions.assertNull(new CheckovScanner(engine) {}.getExecutionIdentity(config).version());
			CheckovProvidedRuleDto rule = new CheckovProvidedRuleDto();
			rule.setName("TEST");
			// rather than test that checkov finds anything (I'm not testing checkov), test that the
			// directory scan doesn't throw issues
			Assertions.assertFalse(engine.runCheckovDirectoryScan(targetDirectory, Arrays.asList(rule)).has("errors"));
			Files.writeString(targetDirectory.resolve("invalid.tf"), "resource \"aws_s3_bucket\" \"broken\" {");
			Assertions.assertTrue(engine.runCheckovDirectoryScan(targetDirectory, List.of(selected)).has("errors"),
					"Quiet output must retain parsing failure evidence");
		} finally {
			if (targetDirectory != null) {
				FileUtils.deleteQuietly(targetDirectory.toFile());
			}
		}
	}

	private void assertResultProtocol(Path temporary) {
		var runner = Mockito.mock(ProcessRunner.class);
		var response = new AtomicReference<>(completed(0, "{\"results\":{\"failed_checks\":[]}}"));
		Mockito.when(runner.run(Mockito.any())).thenAnswer(invocation -> {
			ProcessRequest request = invocation.getArgument(0);
			Assertions.assertEquals(Duration.ofMinutes(2), request.timeout());
			Assertions.assertEquals(8 * 1024 * 1024, request.maxOutputBytes());
			var command = request.command();
			if (command.contains("-d")) {
				Assertions.assertTrue(command.get(2).contains("sys.exit(checkov.run())"));
				return response.get();
			}
			if (command.contains("-v")) return completed(0, "2.0.257");
			if (command.getFirst().equals("pip3")) return completed(0, "pip");
			if (command.getLast().contains("major")) return completed(0, "3");
			if (command.getLast().contains("minor")) return completed(0, "7");
			return completed(0, "{\"python\":\"3.7.0\",\"checkov\":\"2.0.257\",\"checks\":[\"CKV_AWS_62\"]}");
		});
		var engine = new CheckovEngine(runner);
		var selected = new CheckovProvidedRuleDto();
		selected.setName("CKV_AWS_62");
		var checks = List.of(selected);
		String failed = "{\"check_id\":\"CKV_AWS_62\",\"file_path\":\"/main.tf\",\"file_line_range\":[1,2]}";
		String findings = "{\"results\":{\"failed_checks\":[" + failed + "]}}";
		for (int exit : List.of(0, 1)) {
			response.set(completed(exit, findings));
			var report = engine.runCheckovDirectoryScan(temporary, checks);
			Assertions.assertFalse(report.has("errors"), "Findings are valid for exit " + exit);
			Assertions.assertEquals(1, report.getAsJsonObject("results").getAsJsonArray("failed_checks").size());
		}
		response.set(completed(1, "[" + findings + "," + findings + "]"));
		Assertions.assertEquals(2, engine.runCheckovDirectoryScan(temporary, checks)
				.getAsJsonObject("results").getAsJsonArray("failed_checks").size());
		for (String parsingErrors : List.of(
				"{\"results\":{\"failed_checks\":[],\"parsing_errors\":[\"private-marker\"]}}",
				"{\"results\":{\"failed_checks\":[]},\"summary\":{\"parsing_errors\":1}}")) {
			response.set(completed(0, parsingErrors));
			var parsing = engine.runCheckovDirectoryScan(temporary, checks);
			Assertions.assertTrue(parsing.has("errors"));
			Assertions.assertFalse(parsing.toString().contains("private-marker"));
		}
		for (var invalid : List.of(
				completed(1, "{\"results\":{\"failed_checks\":[]}}"),
				completed(2, findings), completed(7, ""),
				completed(0, ""), completed(0, "null"), completed(0, "{}"),
				completed(0, "private-marker"),
				new ProcessResult(-1, "", "", true, false, false, Duration.ZERO),
				new ProcessResult(0, findings, "", false, true, false, Duration.ZERO),
				new ProcessResult(0, findings, "", false, false, true, Duration.ZERO),
				new ProcessResult(0, findings, "private-marker", false, false, false, Duration.ZERO))) {
			response.set(invalid);
			var report = engine.runCheckovDirectoryScan(temporary.resolve("private-marker"), checks);
			Assertions.assertTrue(report.has("errors"), "Incomplete outcome: " + invalid.exitCode());
			Assertions.assertFalse(report.get("errors").getAsString().contains("private-marker"));
		}
		Mockito.doThrow(new IllegalStateException("private-marker")).when(runner).run(Mockito.any());
		Assertions.assertFalse(engine.runCheckovDirectoryScan(temporary, checks).toString().contains("private-marker"));
		Mockito.reset(runner);
		Mockito.when(runner.run(Mockito.any())).thenAnswer(invocation -> {
			ProcessRequest request = invocation.getArgument(0);
			if (request.command().contains("-v")) return completed(0, "2.0.257-other");
			if (request.command().getLast().contains("major")) return completed(0, "3");
			if (request.command().getLast().contains("minor")) return completed(0, "7");
			return completed(0, "pip");
		});
		Assertions.assertThrows(RuntimeException.class, () -> new CheckovEngine(runner),
				"Version prefix matches must not qualify as an installed engine");
	}

	private static ProcessResult completed(int exit, String stdout) {
		return new ProcessResult(exit, stdout, "", false, false, false, Duration.ZERO);
	}
}
