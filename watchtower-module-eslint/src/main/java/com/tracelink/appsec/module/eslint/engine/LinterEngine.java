package com.tracelink.appsec.module.eslint.engine;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.tracelink.appsec.module.eslint.engine.json.CategoryDefinition;
import com.tracelink.appsec.module.eslint.engine.json.LinterMessage;
import com.tracelink.appsec.module.eslint.engine.json.ProvidedRuleDefinition;
import com.tracelink.appsec.module.eslint.model.EsLintProvidedRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDesignation;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

/**
 * The primary ESLint execution class. Ensures that Node, ESLint and Estraverse are installed at the
 * correct version, and to handle execution of JavaScript functions for ESLint features. If this
 * class cannot initialize properly, Watchtower should not start up.
 *
 * @author mcool
 */
@Service
public final class LinterEngine {
	private static final Gson GSON = new Gson();
	private static final TypeToken<List<ProvidedRuleDefinition>> CORE_RULES_TYPE_TOKEN =
			new TypeToken<List<ProvidedRuleDefinition>>() {
			};
	private TypeToken<List<CategoryDefinition>> CORE_RULESETS_TYPE_TOKEN =
			new TypeToken<List<CategoryDefinition>>() {
			};
	public static final TypeToken<List<LinterMessage>> MESSAGES_TYPE_TOKEN =
			new TypeToken<List<LinterMessage>>() {
			};

	private static final String LINTER_SCAN = "linter_scan.js";
	private static final String LINTER_PARSE = "linter_parse.js";

	private static final int NODE_VERSION_MAJOR = 12;
	private static final String ESLINT_VERSION = "7.24.0";

	// Note: LOG is not static so we can write to it before engine instance has been constructed
	private final Logger LOG = LoggerFactory.getLogger(LinterEngine.class);
	private final Path eslintDirectory;
	private Map<String, EsLintProvidedRuleDto> coreRules;
	private List<RulesetDto> coreRulesets;

	public LinterEngine() {
		try {
			// Create ESLint directory
			eslintDirectory = Files.createDirectories(Paths.get("eslint_work")).toAbsolutePath();
			LOG.info("Using ESLint directory: " + eslintDirectory.toString());
			// Copy JS resources to ESLint directory
			copyJsResources(eslintDirectory);
			// Check node version
			checkNodeVersion();
			LOG.info("Node installed correctly");
			// Install ESLint and check version
			installNpmPackageAtVersion("eslint", ESLINT_VERSION);
			LOG.info("ESLint installed correctly");
		} catch (Exception e) {
			throw new RuntimeException("Failed to initialize ESLint Engine", e);
		}
	}

	/**
	 * Gets the map of ESLint core rules. The JS function is only run once, and then the map is
	 * stored in this class.
	 *
	 * @return map of core rules, including descriptions and external URLs for each
	 */
	public Map<String, EsLintProvidedRuleDto> getCoreRules() {
		if (coreRules == null) {
			makeCoreRulesRulesets();
		}
		return coreRules;
	}

	public List<RulesetDto> getCoreRulesets() {
		if (coreRulesets == null) {
			makeCoreRulesRulesets();
		}
		return coreRulesets;
	}

	private void makeCoreRulesRulesets() {
		ProcessResult coreRulesResult = executeJsFunction(LINTER_PARSE, "getCoreRules");
		ProcessResult coreRulesetsResult = executeJsFunction(LINTER_PARSE, "getCoreCategories");
		if (coreRulesResult.hasErrors()) {
			LOG.warn("Errors getting core rules for ESLint:\n" + coreRulesResult.getErrors());
		}
		if (coreRulesetsResult.hasErrors()) {
			LOG.warn("Errors getting core rulesets for ESLint:\n" + coreRulesResult.getErrors());
		}
		Map<String, String> coreRulesetsDescriptionMap;
		if (coreRulesetsResult.hasResults()) {
			List<CategoryDefinition> categoryDefinitions =
					GSON.fromJson(coreRulesetsResult.getResults(),
							CORE_RULESETS_TYPE_TOKEN.getType());
			coreRulesetsDescriptionMap = categoryDefinitions.stream()
					.collect(Collectors.toMap(CategoryDefinition::getName,
							(c -> {
								String desc = c.getDescription();
								if (desc.endsWith(":")) {
									desc = StringUtils.chop(desc);
								}
								return desc;
							}), (f, s) -> s, TreeMap::new));
		} else {
			coreRulesetsDescriptionMap = Collections.emptyMap();
		}
		if (coreRulesResult.hasResults()) {
			Map<String, EsLintProvidedRuleDto> rulesMap =
					new TreeMap<String, EsLintProvidedRuleDto>();
			Map<String, RulesetDto> rulesetsMap = new TreeMap<String, RulesetDto>();

			List<ProvidedRuleDefinition> providedRules = GSON
					.fromJson(coreRulesResult.getResults(), CORE_RULES_TYPE_TOKEN.getType());
			for (ProvidedRuleDefinition def : providedRules) {
				EsLintProvidedRuleDto rule = new EsLintProvidedRuleDto();
				rule.setName(def.getName());
				rule.setMessage(def.getDescription());
				rule.setExternalUrl(def.getUrl());
				rule.setPriority(RulePriority.LOW);

				rulesMap.put(rule.getName(), rule);
				RulesetDto ruleset = rulesetsMap.get(def.getCategory());
				if (ruleset == null) {
					ruleset = new RulesetDto();
					ruleset.setName(def.getCategory());
					ruleset.setDescription(coreRulesetsDescriptionMap.containsKey(def.getCategory())
							? coreRulesetsDescriptionMap.get(def.getCategory())
							: "Ruleset for EsLint Category " + def.getCategory());
					ruleset.setDesignation(RulesetDesignation.PROVIDED);
				}
				ruleset.getRules().add(rule);
				rulesetsMap.put(def.getCategory(), ruleset);
			}

			coreRules = rulesMap;
			coreRulesets = rulesetsMap.values().stream().sorted().collect(Collectors.toList());

		} else {
			coreRules = Collections.emptyMap();
			coreRulesets = Collections.emptyList();
		}
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
		// Copy JS resources to ESLint directory, overwriting any existing files
		String[] resources = {LINTER_SCAN, LINTER_PARSE};
		for (String resource : resources) {
			Path dest = targetDir.resolve(resource);
			try (InputStream is = getClass().getClassLoader()
					.getResourceAsStream("js/" + resource)) {
				FileUtils.copyToFile(is, dest.toFile());
			}
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
		// Get installed version of package to confirm
		List<String> versionCommand = Arrays
				.asList("npm", "list", "--depth=0");
		ProcessResult versionResult = runCommand(versionCommand);
		// if the package is at the right version, move on. Otherwise log errors
		if (versionResult.hasResults()) {
			String targetString = npmPackage + "@" + version;
			if (versionResult.getResults().contains(targetString)) {
				LOG.info(targetString + " already installed");
				return;
			}
		} else if (versionResult.hasErrors()) {
			LOG.warn("Errors getting version of NPM package \"" + npmPackage + "\":\n"
					+ versionResult.getErrors());
		}

		// now install since package doesn't exist
		String npmPackageCoordinates = npmPackage + "@" + version;
		LOG.info("Installing " + npmPackage);
		// Run command to install NPM package
		List<String> installCommand = new ArrayList<>(
				Arrays.asList("npm", "install", npmPackageCoordinates, "--loglevel=error",
						"--no-fund", "--no-audit"));
		installCommand.addAll(Arrays.asList(args));

		ProcessResult installResult = runCommand(installCommand);
		versionResult = runCommand(versionCommand);

		// if the npm list has the right package at the right version, move on.
		// Otherwise log everything about the install and list and throw exception
		if (!versionResult.hasResults()
				|| !versionResult.getResults().contains(npmPackageCoordinates)) {
			// log all output to help triage
			if (installResult.hasErrors()) {
				LOG.warn("Errors installing NPM package \"" + npmPackage + "\":\n" + installResult
						.getErrors());
			}
			if (installResult.hasResults()) {
				LOG.warn("Install Output: " + installResult.getResults());
			}
			if (versionResult.hasErrors()) {
				LOG.warn("Errors getting version of NPM package \"" + npmPackage + "\":\n"
						+ versionResult.getErrors());
			}
			if (versionResult.hasResults()) {
				LOG.warn("Version Check Output: " + versionResult.getResults());
			}
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
		Process p = null;
		try {
			p = pb.start();
			results = IOUtils.toString(p.getInputStream(), Charset.defaultCharset()).trim();
			errors = IOUtils.toString(p.getErrorStream(), Charset.defaultCharset()).trim();
		} catch (IOException e) {
			LOG.error("Failed to run command '" + String.join(" ", command), e);
		} finally {
			if (p != null) {
				p.destroy();
			}
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
