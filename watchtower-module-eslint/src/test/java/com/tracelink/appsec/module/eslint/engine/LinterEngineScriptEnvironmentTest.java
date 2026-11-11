package com.tracelink.appsec.module.eslint.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import com.google.gson.Gson;
import com.tracelink.appsec.watchtower.core.process.ProcessRequest;
import com.tracelink.appsec.watchtower.core.process.ProcessRunner;

/**
 * ESLint rules are JavaScript written by rule authors and run in a node child process. The child
 * must not inherit the server's environment, which holds database, AWS and API credentials.
 */
class LinterEngineScriptEnvironmentTest {

	private static final Set<String> ALLOWED = Set.of("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL");

	@Test
	void theChildKeepsOnlyWhatNodeNeedsToStart() {
		Map<String, String> server = Map.of("PATH", "/usr/bin", "HOME", "/home/watchtoweruser",
				"TMPDIR", "/tmp", "LANG", "C.UTF-8", "LC_ALL", "C.UTF-8",
				"AWS_SECRET_ACCESS_KEY", "never-for-the-child", "AWS_ACCESS_KEY_ID", "never",
				"JDBC_URL", "jdbc:mysql://db/watchtower", "OPENAI_API_KEY", "never",
				"WATCHTOWER_BOOTSTRAP_ADMIN_PASSWORD", "never");

		Map<String, String> child = LinterEngine.scriptEnvironment(server);

		assertEquals(Map.of("PATH", "/usr/bin", "HOME", "/home/watchtoweruser", "TMPDIR", "/tmp",
				"LANG", "C.UTF-8", "LC_ALL", "C.UTF-8"), child);
	}

	@Test
	void anUnsetVariableIsLeftOutRatherThanPassedAsNull() {
		Map<String, String> child = LinterEngine.scriptEnvironment(Map.of("PATH", "/usr/bin"));

		assertEquals(Map.of("PATH", "/usr/bin"), child);
	}

	@Test
	void scriptRunsGetTheStrippedEnvironmentWithTheSameBounds() throws Exception {
		Path directory = Files.createTempDirectory("eslint-env-test");
		try {
			ProcessRequest request = LinterEngine.scriptRequest(List.of("node", "-v"), directory);

			assertNotNull(request.environment(), "null would mean the child inherits everything");
			assertTrue(ALLOWED.containsAll(request.environment().keySet()),
					"unexpected variables: " + request.environment().keySet());
			assertEquals(Duration.ofMinutes(2), request.timeout());
			assertEquals(8 * 1024 * 1024, request.maxOutputBytes());
		} finally {
			FileUtils.deleteDirectory(directory.toFile());
		}
	}

	@Test
	void aRealNodeProcessSeesNoServerSecrets() throws Exception {
		Assumptions.assumeTrue(
				System.getenv().keySet().stream().anyMatch(name -> !ALLOWED.contains(name)),
				"the test JVM has no variable that should be hidden");
		Path directory = Files.createTempDirectory("eslint-env-test");
		try {
			Assumptions.assumeTrue(nodeIsInstalled(directory), "node is not installed here");

			List<String> list = List.of("node", "-p", "JSON.stringify(Object.keys(process.env))");
			// Some systems add variables to every process (macOS adds __CF_USER_TEXT_ENCODING), so
			// what an empty environment already contains is not the server's doing.
			var bare = new ProcessRunner().run(new ProcessRequest(list, directory,
					Duration.ofSeconds(20), 4096, Map.of()));
			assertTrue(bare.isSuccess(), bare.stderr());
			Set<String> addedByTheSystem =
					Set.of(new Gson().fromJson(bare.stdout().trim(), String[].class));

			var result = new ProcessRunner().run(LinterEngine.scriptRequest(list, directory));

			assertTrue(result.isSuccess(), result.stderr());
			String[] seen = new Gson().fromJson(result.stdout().trim(), String[].class);
			for (String name : seen) {
				assertTrue(ALLOWED.contains(name) || addedByTheSystem.contains(name),
						"the child can read " + name);
			}
		} finally {
			FileUtils.deleteDirectory(directory.toFile());
		}
	}

	private static boolean nodeIsInstalled(Path directory) {
		try {
			return new ProcessRunner().run(new ProcessRequest(List.of("node", "-v"), directory,
					Duration.ofSeconds(20), 4096)).isSuccess();
		} catch (RuntimeException e) {
			return false;
		}
	}
}
