package com.tracelink.appsec.module.betterleaks.engine;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;

import com.tracelink.appsec.watchtower.core.process.ProcessExecutionException;
import com.tracelink.appsec.watchtower.core.process.ProcessRequest;
import com.tracelink.appsec.watchtower.core.process.ProcessResult;
import com.tracelink.appsec.watchtower.core.process.ProcessRunner;
import com.tracelink.appsec.watchtower.test.logging.LogWatchExtension;

public class BetterleaksEngineTest {

	/** Synthetic, split so that no secrets scanner flags this source file. */
	private static final String FAKE_SECRET = "ghp_" + "Xa9Bc3De5Fg7Hi1Jk3Lm5No7Pq9Rs1Tu3Vw5";

	@TempDir
	Path target;

	@RegisterExtension
	LogWatchExtension logWatcher = LogWatchExtension.forClass(BetterleaksEngine.class);

	private ProcessRunner runner;

	private BetterleaksEngine engine;

	@BeforeEach
	public void setup() {
		runner = BDDMockito.mock(ProcessRunner.class);
		engine = new BetterleaksEngine(runner, "/opt/bin/betterleaks");
	}

	private static ProcessResult result(int exitCode, String stdout, String stderr,
			boolean timedOut, boolean stdoutTruncated) {
		return new ProcessResult(exitCode, stdout, stderr, timedOut, stdoutTruncated, false,
				Duration.ofMillis(5));
	}

	private void givenProcessReturns(ProcessResult processResult) {
		BDDMockito.when(runner.run(BDDMockito.any())).thenReturn(processResult);
	}

	@Test
	public void testCommandAlwaysRedactsAndDisablesEveryDeveloperBypass() {
		Path config = Path.of("/tmp/bl/config.toml");
		Path ignore = Path.of("/tmp/bl/empty.ignore");

		List<String> command =
				engine.buildCommand(config, ignore, List.of("github-pat", "aws-access-token"));

		Assertions.assertEquals(List.of("/opt/bin/betterleaks", "dir",
				"--no-banner", "--no-color", "--log-level", "warn",
				"--config", config.toString(),
				"--gitleaks-ignore-path", ignore.toString(),
				"--ignore-gitleaks-allow",
				"--redact",
				"--exit-code", "0",
				"--report-format", "json", "--report-path", "-",
				"--enable-rule", "aws-access-token,github-pat",
				// Scanned from inside the target, so paths are repository-relative.
				"."), command);
	}

	@Test
	public void testValidationCommandOnlyAddsBoundedValidationFlags() {
		Path config = Path.of("/tmp/bl/config.toml");
		Path ignore = Path.of("/tmp/bl/empty.ignore");

		List<String> command = engine.buildCommand(config, ignore, List.of("github-pat"), true);

		Assertions.assertEquals(engine.buildCommand(config, ignore, List.of("github-pat")),
				command.stream().filter(arg -> !List.of("--validation", "--validation-timeout",
						"10s", "--validation-workers", "1", "--validation-max-requests", "1")
						.contains(arg)).toList());
		MatcherAssert.assertThat(command, Matchers.hasItems("--validation", "--redact"));
		Assertions.assertEquals(".", command.get(command.size() - 1));
	}

	@Test
	public void testValidateRunsOneRuleWithValidationAndParsesTheStatus() throws Exception {
		BDDMockito.when(runner.run(BDDMockito.any())).thenAnswer(invocation -> {
			ProcessRequest request = invocation.getArgument(0);
			Assertions.assertEquals(target, request.workingDirectory());
			Assertions.assertEquals("github-pat", argAfter(request.command(), "--enable-rule"));
			MatcherAssert.assertThat(request.command(), Matchers.hasItem("--validation"));
			return result(0, "[{\"RuleID\":\"github-pat\",\"File\":\"window.txt\","
					+ "\"StartLine\":6,\"ValidationStatus\":\"valid\"}]", "", false, false);
		});

		Assertions.assertEquals(
				List.of(new BetterleaksValidation("github-pat", "window.txt", 6, "valid")),
				engine.validate(target, "github-pat"));
	}

	@Test
	public void testValidateRefusesAMalformedRuleId() {
		Assertions.assertThrows(BetterleaksScanException.class,
				() -> engine.validate(target, "bad id; rm"));
		BDDMockito.verifyNoInteractions(runner);
	}

	@Test
	public void testValidateFailureIsAScanException() {
		givenProcessReturns(result(1, "", "boom", false, false));

		Assertions.assertThrows(BetterleaksScanException.class,
				() -> engine.validate(target, "github-pat"));
	}

	@Test
	public void testScanRunsInsideTheTargetWithTheRenderedAllowlist() throws Exception {
		List<com.tracelink.appsec.module.betterleaks.allowlist.BetterleaksAllowlistEntry> allowlist =
				List.of(new com.tracelink.appsec.module.betterleaks.allowlist.BetterleaksAllowlistEntry(
						com.tracelink.appsec.module.betterleaks.allowlist.BetterleaksAllowlistScope.GLOBAL,
						null, "src/test/**", null));
		BDDMockito.when(runner.run(BDDMockito.any())).thenAnswer(invocation -> {
			ProcessRequest request = invocation.getArgument(0);
			Assertions.assertEquals(target, request.workingDirectory());
			Assertions.assertEquals(BetterleaksConfigRenderer.render(allowlist),
					Files.readString(Path.of(argAfter(request.command(), "--config"))));
			return result(0, "null", "", false, false);
		});

		engine.scan(target, List.of("github-pat"), allowlist);

		BDDMockito.verify(runner).run(BDDMockito.any());
	}

	@Test
	public void testMalformedRuleIdIsRefusedBeforeAnythingRuns() {
		BetterleaksScanException e = Assertions.assertThrows(BetterleaksScanException.class,
				() -> engine.scan(target, List.of("--config=/etc/passwd")));

		Assertions.assertEquals(BetterleaksScanException.Reason.INVALID_RULE, e.getReason());
		BDDMockito.verifyNoInteractions(runner);
	}

	@Test
	public void testScanRunsWithAWatchtowerOwnedConfigOutsideTheScannedTree() throws Exception {
		AtomicReference<Path> configSeen = new AtomicReference<>();
		BDDMockito.when(runner.run(BDDMockito.any())).thenAnswer(invocation -> {
			ProcessRequest request = invocation.getArgument(0);
			Path config = Path.of(argAfter(request.command(), "--config"));
			configSeen.set(config);
			Assertions.assertEquals(BetterleaksConfigRenderer.BASE_CONFIG,
					Files.readString(config));
			Assertions.assertFalse(config.startsWith(target),
					"a config inside the target would itself be scanned");
			Assertions.assertEquals(Set.of(PosixFilePermission.OWNER_READ,
					PosixFilePermission.OWNER_WRITE), Files.getPosixFilePermissions(config));
			Assertions.assertEquals(0L,
					Files.size(Path.of(argAfter(request.command(), "--gitleaks-ignore-path"))));
			return result(0, "null", "", false, false);
		});

		Assertions.assertEquals(List.of(), engine.scan(target, List.of("github-pat")));

		Assertions.assertFalse(Files.exists(configSeen.get().getParent()),
				"the temp config directory must be removed after the scan");
	}

	@Test
	public void testScanBoundsTheProcessTimeAndOutput() throws Exception {
		givenProcessReturns(result(0, "[]", "", false, false));

		engine.scan(target, List.of("github-pat"));

		ArgumentCaptor<ProcessRequest> request = ArgumentCaptor.forClass(ProcessRequest.class);
		BDDMockito.verify(runner).run(request.capture());
		Assertions.assertEquals(BetterleaksEngine.SCAN_TIMEOUT, request.getValue().timeout());
		Assertions.assertEquals(BetterleaksEngine.MAX_OUTPUT_BYTES,
				request.getValue().maxOutputBytes());
	}

	@Test
	public void testScanDeletesIgnoreFilesADeveloperCouldCommitToHideASecret() throws Exception {
		// betterleaks honours a .betterleaksignore at the scan root even when
		// --gitleaks-ignore-path points elsewhere (verified against 1.8.1).
		Path rootIgnore = Files.writeString(target.resolve(".betterleaksignore"), "x:y:1");
		Path nestedIgnore = Files.writeString(
				Files.createDirectories(target.resolve("sub")).resolve(".gitleaksignore"), "x");
		Path ordinary = Files.writeString(target.resolve("keep.txt"), "x");
		BDDMockito.when(runner.run(BDDMockito.any())).thenAnswer(invocation -> {
			Assertions.assertFalse(Files.exists(rootIgnore));
			Assertions.assertFalse(Files.exists(nestedIgnore));
			return result(0, "null", "", false, false);
		});

		engine.scan(target, List.of("github-pat"));

		Assertions.assertTrue(Files.exists(ordinary));
	}

	@Test
	public void testNoRulesMeansNoProcess() throws Exception {
		Assertions.assertEquals(List.of(), engine.scan(target, List.of()));
		BDDMockito.verifyNoInteractions(runner);
	}

	@Test
	public void testNonZeroExitIsAFailureThatNeverQuotesStderr() {
		givenProcessReturns(result(1, "", "FTL leaked " + FAKE_SECRET, false, false));

		BetterleaksScanException e = Assertions.assertThrows(BetterleaksScanException.class,
				() -> engine.scan(target, List.of("github-pat")));

		MatcherAssert.assertThat(e.getMessage(), Matchers.containsString("exit code 1"));
		MatcherAssert.assertThat(e.getMessage(), Matchers.not(Matchers.containsString(FAKE_SECRET)));
	}

	@Test
	public void testFailureLogNeverContainsScannerOutput() {
		// Betterleaks redacts its own logs, but Watchtower must not depend on that: a leak here
		// would put the secret into CloudWatch.
		givenProcessReturns(result(1, FAKE_SECRET, "FTL leaked " + FAKE_SECRET, false, false));

		Assertions.assertThrows(BetterleaksScanException.class,
				() -> engine.scan(target, List.of("github-pat")));

		Assertions.assertFalse(logWatcher.getFormattedMessages().isEmpty(),
				"the failure should still be logged");
		logWatcher.getFormattedMessages().forEach(message -> MatcherAssert.assertThat(message,
				Matchers.not(Matchers.containsString(FAKE_SECRET))));
	}

	@Test
	public void testTimeoutIsAFailure() {
		givenProcessReturns(result(ProcessResult.TIMED_OUT_EXIT_CODE, "", "", true, false));

		BetterleaksScanException e = Assertions.assertThrows(BetterleaksScanException.class,
				() -> engine.scan(target, List.of("github-pat")));

		MatcherAssert.assertThat(e.getMessage(), Matchers.containsString("timed out"));
		Assertions.assertEquals(BetterleaksScanException.Reason.TIMEOUT, e.getReason());
	}

	@Test
	public void testTruncatedOutputIsAFailureNotAPartialResult() {
		givenProcessReturns(result(0, "[{\"RuleID\":\"github-pat\"", "", false, true));

		BetterleaksScanException e = Assertions.assertThrows(BetterleaksScanException.class,
				() -> engine.scan(target, List.of("github-pat")));

		MatcherAssert.assertThat(e.getMessage(), Matchers.containsString("output limit"));
	}

	@Test
	public void testBinaryThatCannotStartIsAFailure() {
		BDDMockito.when(runner.run(BDDMockito.any()))
				.thenThrow(new ProcessExecutionException("Cannot start process", null));

		Assertions.assertThrows(BetterleaksScanException.class,
				() -> engine.scan(target, List.of("github-pat")));
	}

	@Test
	public void testParsesFindingsFromStdout() throws Exception {
		givenProcessReturns(result(0, "[{\"RuleID\":\"github-pat\",\"File\":\"" + target
				+ "/a.java\",\"StartLine\":4,\"Secret\":\"REDACTED\"}]", "", false, false));

		Assertions.assertEquals(
				List.of(new BetterleaksFinding("github-pat", target + "/a.java", 4)),
				engine.scan(target, List.of("github-pat")));
	}

	@Test
	public void testBinaryPathComesFromTheEnvironmentOrPath() {
		Assertions.assertEquals("/usr/local/bin/betterleaks", BetterleaksEngine.resolveBinary(
				Map.of(BetterleaksEngine.BINARY_PATH_ENV, "/usr/local/bin/betterleaks")));
		Assertions.assertEquals("betterleaks", BetterleaksEngine.resolveBinary(Map.of()));
		Assertions.assertEquals("betterleaks",
				BetterleaksEngine.resolveBinary(Map.of(BetterleaksEngine.BINARY_PATH_ENV, " ")));
	}

	@Test
	public void testIsAvailableRunsTheVersionCommand() {
		givenProcessReturns(result(0, "1.8.1\n", "", false, false));
		Assertions.assertTrue(engine.isAvailable());

		BDDMockito.when(runner.run(BDDMockito.any()))
				.thenThrow(new ProcessExecutionException("Cannot start process", null));
		Assertions.assertFalse(engine.isAvailable());
	}

	@Test
	public void aDiagnosticLineLosesTheColourCodesAndTheLogPrefix() {
		// Dev E2E G02: the designer showed "\u001b[90m4:57PM\u001b[0m \u001b[31mFTL\u001b[0m ..." to the user.
		String raw = "\u001b[90m4:57PM\u001b[0m \u001b[31mFTL\u001b[0m \u001b[1munable to load config, err: "
				+ "custom-t2: invalid regex\u001b[0m";

		Assertions.assertEquals("unable to load config, err: custom-t2: invalid regex",
				BetterleaksEngine.plainDiagnostic(raw));
		Assertions.assertEquals("a plain line", BetterleaksEngine.plainDiagnostic("a plain line"));
	}

	private static String argAfter(List<String> command, String flag) {
		return command.get(command.indexOf(flag) + 1);
	}
}
