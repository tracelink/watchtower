package com.tracelink.appsec.watchtower.core.process;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.api.io.TempDir;

import com.tracelink.appsec.watchtower.core.logging.CoreLogWatchExtension;

import ch.qos.logback.classic.Level;

@DisabledOnOs(OS.WINDOWS)
public class ProcessRunnerTest {

	private static final Duration TIMEOUT = Duration.ofSeconds(10);
	private static final long ONE_MB = 1024L * 1024L;

	@RegisterExtension
	public final CoreLogWatchExtension logWatcher =
			CoreLogWatchExtension.forClass(ProcessRunner.class);

	private final ProcessRunner runner = new ProcessRunner();

	@Test
	public void testCapturesStdoutAndZeroExit() {
		ProcessResult result = runner.run(request("echo hello"));

		Assertions.assertEquals(0, result.exitCode());
		Assertions.assertTrue(result.isSuccess());
		Assertions.assertEquals("hello\n", result.stdout());
		Assertions.assertFalse(result.timedOut());
		ProcessResult isolated = runner.run(new ProcessRequest(List.of("/usr/bin/env"), null, TIMEOUT, ONE_MB,
				java.util.Map.of("WATCHTOWER_PARSER_FIXTURE", "configured")));
		Assertions.assertEquals("WATCHTOWER_PARSER_FIXTURE=configured\n", isolated.stdout());
	}

	@Test
	public void testCapturesNonZeroExitAndStderr() {
		ProcessResult result = runner.run(request("echo oops 1>&2; exit 3"));

		Assertions.assertEquals(3, result.exitCode());
		Assertions.assertFalse(result.isSuccess());
		Assertions.assertEquals("oops\n", result.stderr());
	}

	@Test
	public void testTimeoutKillsProcess() {
		long start = System.nanoTime();
		ProcessResult result = runner.run(new ProcessRequest(List.of("sh", "-c", "sleep 30"),
				null, Duration.ofMillis(300), ONE_MB));
		Duration elapsed = Duration.ofNanos(System.nanoTime() - start);

		Assertions.assertTrue(result.timedOut());
		Assertions.assertFalse(result.isSuccess());
		Assertions.assertTrue(elapsed.compareTo(Duration.ofSeconds(5)) < 0,
				"timeout took " + elapsed);
	}

	@Test
	public void testLargeStderrDoesNotDeadlockAndIsTruncated() {
		String script = "head -c 10485760 /dev/zero | tr '\\0' 'e' 1>&2; echo done";

		ProcessResult result = runner.run(new ProcessRequest(List.of("sh", "-c", script), null,
				TIMEOUT, ONE_MB));

		Assertions.assertFalse(result.timedOut());
		Assertions.assertEquals("done\n", result.stdout());
		Assertions.assertTrue(result.stderrTruncated());
		Assertions.assertEquals(ONE_MB, result.stderr().length());
	}

	@Test
	public void testStdoutTruncatedAtCap() {
		ProcessResult result = runner.run(new ProcessRequest(
				List.of("sh", "-c", "head -c 5000 /dev/zero | tr '\\0' 'x'"), null, TIMEOUT, 100));

		Assertions.assertTrue(result.stdoutTruncated());
		Assertions.assertEquals(100, result.stdout().length());
		Assertions.assertEquals(0, result.exitCode());
	}

	@Test
	public void testUsesWorkingDirectory(@TempDir Path dir) throws Exception {
		ProcessResult result = runner.run(new ProcessRequest(List.of("pwd"), dir, TIMEOUT,
				ONE_MB));

		Assertions.assertEquals(dir.toRealPath().toString(),
				Path.of(result.stdout().trim()).toRealPath().toString());
	}

	@Test
	public void testMissingBinaryThrows() {
		Assertions.assertThrows(ProcessExecutionException.class,
				() -> runner.run(new ProcessRequest(List.of("definitely-not-a-binary-xyz"), null,
						TIMEOUT, ONE_MB)));
	}

	@Test
	public void testInvalidRequestsRejected(@TempDir Path dir) throws Exception {
		Path file = Files.createFile(dir.resolve("file"));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> new ProcessRequest(List.of(), null, TIMEOUT, ONE_MB));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> new ProcessRequest(List.of("sh"), null, Duration.ZERO, ONE_MB));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> new ProcessRequest(List.of("sh"), null, TIMEOUT, 0));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> new ProcessRequest(List.of("sh"), file, TIMEOUT, ONE_MB));
		Assertions.assertThrows(NullPointerException.class,
				() -> new ProcessRequest(null, null, TIMEOUT, ONE_MB));
	}

	@Test
	public void testRequestCommandIsImmutableCopy() {
		List<String> command = new ArrayList<>(List.of("echo", "a"));
		ProcessRequest request = new ProcessRequest(command, null, TIMEOUT, ONE_MB);
		command.add("b");

		Assertions.assertEquals(List.of("echo", "a"), request.command());
		Assertions.assertThrows(UnsupportedOperationException.class,
				() -> request.command().add("c"));
	}

	@Test
	public void testNeverLogsProcessOutput() {
		logWatcher.withLevel(Level.ALL);
		String marker = "SENSITIVE-MARKER-123";

		runner.run(request("echo " + marker + "; echo " + marker + " 1>&2; exit 1"));

		Assertions.assertTrue(
				logWatcher.getMessages().stream().noneMatch(m -> m.contains(marker)),
				"process output must never be logged: " + logWatcher.getMessages());
	}

	private static ProcessRequest request(String script) {
		return new ProcessRequest(List.of("sh", "-c", script), null, TIMEOUT, ONE_MB);
	}
}
