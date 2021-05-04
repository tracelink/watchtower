package com.tracelink.appsec.module.eslint.engine;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.tracelink.appsec.module.eslint.engine.json.LinterMessage;

/**
 * The primary ESLint execution class. Singleton class to ensure that Node, ESLint and Estraverse
 * are installed at the correct version, and to handle execution of JavaScript functions for ESLint
 * features. If this class cannot initialize properly, Watchtower should not start up.
 *
 * @author mcool
 */
public final class LinterEngine {

	private static final LinterEngine INSTANCE = new LinterEngine();

	private static final Gson GSON = new Gson();
	private static final TypeToken<Map<String, Map<String, String>>> CORE_RULES_TYPE_TOKEN =
			new TypeToken<Map<String, Map<String, String>>>() {
			};
	public static final TypeToken<List<LinterMessage>> MESSAGES_TYPE_TOKEN =
			new TypeToken<List<LinterMessage>>() {
			};

	private static final String LINTER_SCAN = "linter_scan.js";
	private static final String LINTER_PARSE = "linter_parse.js";

	private static final int NODE_VERSION_MAJOR = 12;
	private static final String ESLINT_VERSION = "7.24.0";
	private static final String ESTRAVERSE_VERSION = "5.2.0";

	// Note: LOG is not static so we can write to it before engine instance has been constructed
	private final Logger LOG = LoggerFactory.getLogger(LinterEngine.class);
	private final Path eslintDirectory;
	private Map<String, Map<String, String>> coreRules;

	private LinterEngine() {
		try {
			// Create ESLint directory
			eslintDirectory = Files.createTempDirectory(null).toAbsolutePath();
			if (eslintDirectory.toFile().exists()) {
				FileUtils.forceDelete(eslintDirectory.toFile());
			}
			// Copy JS resources to ESLint directory
			copyJsResources(eslintDirectory);
			// Check node version
			checkNodeVersion();
			// Install ESLint and check version
			installNpmPackageAtVersion("eslint", ESLINT_VERSION, "--save-dev");
			// Install Estraverse and check version
			installNpmPackageAtVersion("estraverse", ESTRAVERSE_VERSION);
		} catch (Exception e) {
			throw new RuntimeException("Failed to initialize ESLint Engine", e);
		}
	}

	/**
	 * Get the singleton EsLintEngine instance.
	 *
	 * @return the EsLintEngine instance
	 */
	public static LinterEngine getInstance() {
		return INSTANCE;
	}

	/**
	 * Gets the map of ESLint core rules. The JS function is only run once, and then the map is
	 * stored in this class.
	 *
	 * @return map of core rules, including descriptions and external URLs for each
	 */
	public Map<String, Map<String, String>> getCoreRules() {
		if (coreRules == null) {
			ProcessResult processResult = executeJsFunction(LINTER_PARSE, "getCoreRules");
			if (processResult.hasErrors()) {
				LOG.warn("Errors getting core rules for ESLint:\n" + processResult.getErrors());
			}
			if (processResult.hasResults()) {
				coreRules = GSON
						.fromJson(processResult.getResults(), CORE_RULES_TYPE_TOKEN.getType());
			} else {
				coreRules = Collections.emptyMap();
			}
		}
		return Collections.unmodifiableMap(coreRules);
	}

	/**
	 * Scans the given lines of code with the ESLint Linter, using the ruleset at the given path.
	 *
	 * @param lines     lines of code to scan
	 * @param directory name of directory for source code file
	 * @param file      name of source code file
	 * @param ruleset   path to the ruleset to use for scanning
	 * @return {@link ProcessResult} containing messages from the Linter and/or errors
	 */
	public ProcessResult scanCode(String lines, String directory, String file, String ruleset) {
		return executeJsFunction(LINTER_SCAN, "scanCode", escapeCommandLineArgument(lines),
				directory, file, ruleset);
	}

	/**
	 * Parses the given ruleset using the ESLint Linter and Estraverse.
	 *
	 * @param ruleset ruleset to parse into JSON
	 * @return {@link ProcessResult} containing the ruleset as JSON, or messages from the Linter if
	 *         there are errors
	 */
	public ProcessResult parseRuleset(String ruleset) {
		return executeJsFunction(LINTER_PARSE, "parseRuleset", escapeCommandLineArgument(ruleset));
	}

	/**
	 * Parses the given source code into an AST using the ESLint Linter.
	 *
	 * @param sourceCode source code to parse into AST
	 * @return {@link ProcessResult} containing the AST as JSON, or messages from the Linter if
	 *         there are errors
	 */
	public ProcessResult parseAst(String sourceCode) {
		return executeJsFunction(LINTER_PARSE, "parseAst", escapeCommandLineArgument(sourceCode));
	}

	/**
	 * Copy all JS resource files to ESLint directory and confirm they exist.
	 *
	 * @param targetDir the ESLint directory to copy files to
	 * @throws IOException if the JS files do not exist in the ESLint directory
	 */
	private void copyJsResources(Path targetDir) throws IOException {
		Files.createDirectories(targetDir);
		// Copy JS resources to ESLint directory
		try (InputStream is = getClass().getClassLoader()
				.getResourceAsStream("js/" + LINTER_SCAN)) {
			Path destPath = Files.createFile(targetDir.resolve(LINTER_SCAN));
			OutputStream os = new FileOutputStream(destPath.toFile());
			IOUtils.copy(is, os);
		}
		try (InputStream is = getClass().getClassLoader()
				.getResourceAsStream("js/" + LINTER_PARSE)) {
			Path destPath = Files.createFile(targetDir.resolve(LINTER_PARSE));
			OutputStream os = new FileOutputStream(destPath.toFile());
			IOUtils.copy(is, os);
		}

		// Make sure the JS files exist
		if (!eslintDirectory.resolve(LINTER_SCAN).toFile().exists()) {
			throw new IOException("ESLint Linter scanning code does not exist "
					+ eslintDirectory.resolve(LINTER_SCAN).toAbsolutePath().toString());
		}
		if (!eslintDirectory.resolve(LINTER_PARSE).toFile().exists()) {
			throw new IOException("ESLint Linter parsing code does not exist "
					+ eslintDirectory.resolve(LINTER_PARSE).toAbsolutePath().toString());
		}
	}

	/**
	 * Confirm that the version of Node.js installed meets requirements for ESLint.
	 */
	private void checkNodeVersion() {
		// Check node version
		ProcessResult processResult = runCommand(Arrays.asList("node", "-v"));
		// Log any errors as a warning
		if (processResult.hasErrors()) {
			LOG.warn("Errors while checking node version:\n" + processResult.getErrors());
		}
		// Compare major version number
		if (processResult.hasResults()) {
			int nodeVersionMajor = Integer
					.parseInt(processResult.getResults().substring(1).split("\\.")[0]);
			if (nodeVersionMajor < NODE_VERSION_MAJOR) {
				throw new RuntimeException(
						"Expected Node.js greater than v12.0.0 but received " + processResult
								.getResults());
			}
		}
	}

	/**
	 * Install the given NPM package in the ESLint directory at the given version. Confirm that the
	 * version installed matches the given version.
	 *
	 * @param npmPackage the name of the NPM package to install
	 * @param version    the version of the NPM package to install
	 * @param args       any additional arguments for the npm install command
	 */
	private void installNpmPackageAtVersion(String npmPackage, String version, String... args) {
		// Run command to install NPM package
		List<String> installCommand = new ArrayList<>(
				Arrays.asList("npm", "install", npmPackage + "@" + version, "--loglevel=error"));
		installCommand.addAll(Arrays.asList(args));
		ProcessResult installResult = runCommand(installCommand);
		// If there are errors, log as a warning but continue
		if (installResult.hasErrors()) {
			LOG.warn("Errors installing NPM package \"" + npmPackage + "\":\n" + installResult
					.getErrors());
		}
		// If there are results, log results as info
		if (installResult.hasResults()) {
			LOG.info(installResult.getResults());
		}
		// Get installed version of package to confirm
		List<String> versionCommand = Arrays
				.asList("npm", "list", "--depth=0");
		ProcessResult versionResult = runCommand(versionCommand);
		if (versionResult.hasErrors()) {
			LOG.warn("Errors getting version of NPM package \"" + npmPackage + "\":\n"
					+ versionResult.getErrors());
		}
		// Throw exception if installed version does not match given version, or if result is null
		if (versionResult.hasResults()) {
			String targetString = npmPackage + "@" + version;
			if (!versionResult.getResults().contains(targetString)) {
				throw new RuntimeException(
						"Expected \"" + npmPackage + "\" version " + version
								+ " but received npm list:"
								+ versionResult.getResults());
			}
		} else {
			throw new RuntimeException("Cannot verify installed version of \"" + npmPackage + "\"");
		}
	}

	/**
	 * Executes the given JS function in the given file with the given arguments.
	 *
	 * @param file      name of JS file; should be either 'linter_scan.js' or 'linter_parse.js'
	 * @param function  name of JS function within file
	 * @param arguments arguments for the JS function, if any
	 * @return {@link ProcessResult} containing results and errors from the JS execution
	 */
	private ProcessResult executeJsFunction(String file, String function, String... arguments) {
		List<String> command = Arrays.asList("node", "-p",
				"require('./" + file.split("\\.")[0] + "')." + function +
						(arguments.length == 0 ? "()"
								: "(\"" + String.join("\", \"", arguments) + "\")"));
		return runCommand(command);
	}


	/**
	 * Runs the given command using a {@link ProcessBuilder}.
	 *
	 * @param command the command to run
	 * @return {@link ProcessResult} containing results and errors from command
	 */
	private ProcessResult runCommand(List<String> command) {
		ProcessBuilder pb = new ProcessBuilder(command);
		pb.directory(this.eslintDirectory.toFile());

		String results = null;
		String errors = null;
		try {
			Process p = pb.start();
			results = IOUtils.toString(p.getInputStream(), Charset.defaultCharset()).trim();
			errors = IOUtils.toString(p.getErrorStream(), Charset.defaultCharset()).trim();
		} catch (IOException e) {
			LOG.error("Failed to run command '" + String.join(" ", command), e);
		}
		return new ProcessResult(results, errors);
	}

	/**
	 * Escape newlines and double quotes in the given argument so that it can be passed to the
	 * command line.
	 *
	 * @param argument command line argument to escape
	 * @return escaped argument
	 */
	private String escapeCommandLineArgument(String argument) {
		return argument.replaceAll("\n", "\\\\n").replaceAll("\"", "\\\\\"").replaceAll("\r",
				"\\\\r");
	}
}
