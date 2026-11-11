package com.tracelink.appsec.module.checkov.engine;

import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.tracelink.appsec.module.checkov.model.CheckovProvidedRuleDto;
import com.tracelink.appsec.module.checkov.model.CheckovRuleDefinitionDto;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.process.ProcessRequest;
import com.tracelink.appsec.watchtower.core.process.ProcessResult;
import com.tracelink.appsec.watchtower.core.process.ProcessRunner;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDesignation;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.EngineExecutionIdentity;

import kong.unirest.Unirest;


/**
 * The primary Checkov Execution class. This handles ensuring that python is installed at the
 * correct version, the Checkov binary is setup correctly and at the right version, and manage the
 * execution of Checkov against target code
 * 
 * @author csmith
 *
 */
public class CheckovEngine {
	private static final Logger LOG = LoggerFactory.getLogger(CheckovEngine.class);

	private static final String BRIDGECREW_GUIDELINES =
			"https://www.bridgecrew.cloud/api/v1/guidelines";

	private static final int EXPECTED_PYTHON_VERSION_MAJOR = 3;
	private static final int EXPECTED_PYTHON_VERSION_MINOR = 7;

	private static final String EXPECTED_CHECKOV_VERSION = "2.0.257";
	static final List<String> SCAN_ARGUMENTS = List.of("--quiet", "--no-guide", "-o", "json");
	private final ProcessRunner processRunner;

	private Map<String, RulesetDto> coreRulesets;

	private final Gson gson;

	private List<CheckovProvidedRuleDto> coreRules;

	public CheckovEngine() {
		this(new ProcessRunner());
	}

	CheckovEngine(ProcessRunner processRunner) {
		this.processRunner = processRunner;
		gson = new Gson();
		try {
			testPythonVersion();
			LOG.info("Python installed correctly");
			installCheckov();
			LOG.info("Checkov installed correctly");
		} catch (Exception e) {
			throw new RuntimeException("Failed to create Checkov Engine", e);
		}
	}


	public EngineExecutionIdentity getExecutionIdentity(ICodeScanner scanner, CodeScanConfig config) {
		return CheckovExecutionIdentity.capture(this, scanner, config);
	}

	ProcessResult captureRuntime() {
		return runPythonCommand("-c", "import json, sys; from checkov.version import version; "
				+ "from checkov.common.util.docs_generator import get_checks; "
				+ "print(json.dumps({'python': '.'.join(map(str, sys.version_info[:3])), "
				+ "'checkov': version, 'checks': sorted({row[0] for row in get_checks()})}))");
	}

	private void testPythonVersion() {
		var major = runPythonCommand("-c", "import sys; print(sys.version_info.major)");
		var minor = runPythonCommand("-c", "import sys; print(sys.version_info.minor)");
		if (!isComplete(major) || !isComplete(minor)
				|| Integer.parseInt(major.stdout().trim()) < EXPECTED_PYTHON_VERSION_MAJOR
				|| (Integer.parseInt(major.stdout().trim()) == EXPECTED_PYTHON_VERSION_MAJOR
						&& Integer.parseInt(minor.stdout().trim()) < EXPECTED_PYTHON_VERSION_MINOR)) {
			throw new IllegalStateException("Cannot verify Python version 3.7 or newer");
		}
		if (!isComplete(runPipCommand("-V"))) throw new IllegalStateException("Pip is not installed");
	}

	private void installCheckov() {
		if (hasExpectedVersion(runCheckovCommand("-v"))) return;
		for (boolean user : List.of(false, true)) {
			var arguments = new ArrayList<>(List.of("install", "checkov==" + EXPECTED_CHECKOV_VERSION,
					"--force-reinstall", "--no-cache-dir", "--no-warn-script-location"));
			if (user) arguments.add("--user");
			var installed = runPipCommand(arguments.toArray(String[]::new));
			if (!installed.isSuccess()) LOG.warn("Checkov installation failed: exit={}", installed.exitCode());
			if (hasExpectedVersion(runCheckovCommand("-v"))) return;
		}
		throw new IllegalStateException("Cannot verify Checkov version " + EXPECTED_CHECKOV_VERSION);
	}

	private ProcessResult runPythonCommand(String... arguments) {
		return runExecutable("python3", arguments);
	}

	private ProcessResult runPipCommand(String... arguments) {
		return runExecutable("pip3", arguments);
	}

	private ProcessResult runExecutable(String executable, String... arguments) {
		var command = new ArrayList<>(List.of(executable));
		command.addAll(Arrays.asList(arguments));
		return processRunner.run(new ProcessRequest(command, null, Duration.ofMinutes(2), 8 * 1024 * 1024));
	}

	private ProcessResult runCheckovCommand(String... arguments) {
		var command = new ArrayList<>(List.of("-c",
				"from checkov import main as checkov; import sys; sys.exit(checkov.run());"));
		command.addAll(Arrays.asList(arguments));
		return runPythonCommand(command.toArray(String[]::new));
	}

	static boolean isComplete(ProcessResult result) {
		return result.isSuccess() && !result.stdoutTruncated() && !result.stderrTruncated()
				&& !result.stdout().isBlank() && result.stderr().isBlank();
	}

	private static boolean hasExpectedVersion(ProcessResult result) {
		return isComplete(result) && EXPECTED_CHECKOV_VERSION.equals(result.stdout().trim());
	}

	public Map<String, RulesetDto> getCoreRulesets() {
		if (coreRulesets == null) {
			populateCoreRulesRulesets();
		}
		return coreRulesets;
	}

	public List<CheckovProvidedRuleDto> getCoreRules() {
		if (coreRules == null) {
			populateCoreRulesRulesets();
		}
		return coreRules;
	}

	private void populateCoreRulesRulesets() {
		ProcessResult rulesResult = runCheckovCommand("--list", "--no-guide");
		if (!isComplete(rulesResult)) throw new IllegalStateException("Cannot load Checkov catalog");
		var guidelines = new kong.unirest.json.JSONObject();
		try {
			guidelines = Unirest.get(BRIDGECREW_GUIDELINES).connectTimeout(5000).socketTimeout(5000)
					.asJson().getBody().getObject().getJSONObject("guidelines");
		} catch (RuntimeException exception) {
			LOG.warn("Checkov documentation links unavailable; using catalog definitions");
		}
		final var documentation = guidelines;
		Map<String, RulesetDto> coreRulesets = new TreeMap<>();
		Map<String, CheckovProvidedRuleDto> coreRules = new TreeMap<>();
		Stream.of(rulesResult.stdout().split("\\r?\\n")).skip(2).forEachOrdered(r -> {
			String[] ruleLine = r.split("\\|");
			if (ruleLine.length != 7) {
				return;
			}

			String name = ruleLine[2].trim();

			// make the ruleset name from the rule name CKV_AWS_123 is in the ruleset CKV_AWS
			String[] nameParts = name.split("_");
			if (nameParts.length != 3) {
				throw new IllegalArgumentException("Can't parse rule name " + name);
			}
			String rulesetName = String.join("_", nameParts[0], nameParts[1]);

			// make the definition object
			String type = ruleLine[3].trim();
			String entity = ruleLine[4].trim();
			String message = ruleLine[5].trim();
			String iac = ruleLine[6].trim();

			CheckovRuleDefinitionDto def = new CheckovRuleDefinitionDto();
			def.setType(type);
			def.setEntity(entity);
			def.setIac(iac);

			CheckovProvidedRuleDto rule = coreRules.get(name);
			if (rule == null) {
				rule = new CheckovProvidedRuleDto();
				rule.setName(name);
				rule.setMessage(message);
				String url = documentation.optString(rule.getName(), "#");
				rule.setExternalUrl(url);
				rule.setPriority(RulePriority.LOW);
				coreRules.put(name, rule);
			}
			rule.getDefinitions().add(def);

			RulesetDto ruleset = coreRulesets.get(rulesetName);
			if (ruleset == null) {
				ruleset = new RulesetDto();
				ruleset.setBlockingLevel(RulePriority.LOW);
				ruleset.setDescription(
						"Checkov Provided Ruleset for " + iac + " rules");
				ruleset.setDesignation(RulesetDesignation.PROVIDED);
				ruleset.setName(rulesetName);
				coreRulesets.put(rulesetName, ruleset);
			}
			ruleset.getRules().add(rule);
		});
		if (coreRules.isEmpty()) throw new IllegalStateException("Checkov returned no catalog definitions");
		this.coreRulesets = coreRulesets;
		this.coreRules = coreRules.values().stream().collect(Collectors.toList());
	}

	/**
	 * Execute a checkov scan on a directory, given the supplied checkov rules. This is equivalent
	 * to the checkov command line: <br>
	 * <code>
	 * checkov.py -d {targetDirectory} --quiet --no-guide -o json -c {ruleChecks}
	 * </code>
	 * 
	 * @param targetDirectory the directory to scan
	 * @param ruleChecks      the checks to use
	 * @return a json object of the result from checkov
	 */
	public JsonObject runCheckovDirectoryScan(Path targetDirectory,
			List<CheckovProvidedRuleDto> ruleChecks) {
		try {
			if (ruleChecks.isEmpty()) return normalizeReports(new JsonArray());
			var command = new ArrayList<>(List.of("-d", targetDirectory.toString()));
			command.addAll(SCAN_ARGUMENTS);
			command.addAll(List.of("-c", ruleChecks.stream().map(RuleDto::getName).collect(Collectors.joining(","))));
			var result = runCheckovCommand(command.toArray(String[]::new));
			if (result.timedOut() || result.stdoutTruncated() || result.stderrTruncated()
					|| (result.exitCode() != 0 && result.exitCode() != 1)) {
				return error("Checkov process failed (exit=" + result.exitCode() + ", timeout=" + result.timedOut()
						+ ", truncated=" + (result.stdoutTruncated() || result.stderrTruncated()) + ")");
			}
			var json = normalizeReports(gson.fromJson(result.stdout(), JsonElement.class));
			if (result.exitCode() == 1 && json.getAsJsonObject("results").getAsJsonArray("failed_checks").isEmpty()) {
				json.addProperty("errors", "Checkov exited with failure but reported no failed checks");
			}
			if (!result.stderr().isBlank()) json.addProperty("errors", "Checkov reported diagnostics on stderr");
			return json;
		} catch (RuntimeException exception) {
			// Process arguments, diagnostic output and JSON exceptions can contain source/secrets.
			return error("Cannot execute Checkov or decode its report");
		}
	}

	private static JsonObject error(String message) {
		var result = new JsonObject();
		result.addProperty("errors", message);
		return result;
	}

	private static JsonObject normalizeReports(JsonElement output) {
		if (output == null || output.isJsonNull()) throw new IllegalArgumentException("Missing report");
		var reports = new JsonArray();
		if (output.isJsonArray()) reports = output.getAsJsonArray();
		else reports.add(output);
		var failed = new JsonArray();
		var normalized = new JsonObject();
		for (var report : reports) {
			var object = report.getAsJsonObject();
			var result = object.getAsJsonObject("results");
			var checks = result.getAsJsonArray("failed_checks");
			if (checks == null) throw new IllegalArgumentException("Missing checks");
			for (var check : checks) {
				if (!check.isJsonObject()) throw new IllegalArgumentException("Malformed check");
				failed.add(check);
			}
			for (var section : List.of(object, result)) {
				if (section.has("parsing_errors") && !section.getAsJsonArray("parsing_errors").isEmpty()) {
					normalized.addProperty("errors", "Checkov reported parsing errors");
				}
			}
			// --quiet omits parsing-error details but retains their count in the summary.
			if (object.has("summary")) {
				var summary = object.getAsJsonObject("summary");
				if (summary.has("parsing_errors") && summary.get("parsing_errors").getAsInt() != 0) {
					normalized.addProperty("errors", "Checkov reported parsing errors");
				}
			}
		}
		var results = new JsonObject();
		results.add("failed_checks", failed);
		normalized.add("results", results);
		return normalized;
	}
}
