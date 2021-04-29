package com.tracelink.appsec.module.checkov.engine;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.tracelink.appsec.module.checkov.model.CheckovRuleDto;

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

	private Path checkovBinary;

	private static final String BRIDGECREW_GUIDELINES =
			"https://www.bridgecrew.cloud/api/v1/guidelines";

	private static final int EXPECTED_PYTHON_VERSION_MAJOR = 3;
	private static final int EXPECTED_PYTHON_VERSION_MINOR = 7;

	private static final String EXPECTED_CHECKOV_VERSION = "2.0.40";

	private final Map<String, CheckovRuleDto> coreRules;

	private final Gson gson;

	public CheckovEngine() {
		gson = new Gson();
		try {
			testPythonVersion();
			installCheckov();
			coreRules = Collections.unmodifiableMap(populateCoreRules());
		} catch (Exception e) {
			throw new RuntimeException("Failed to create Checkov Engine", e);
		}
	}

	private void testPythonVersion() throws IOException {
		String pythonMajorVersionNum = runPythonCommand("-c",
				"import sys; print(sys.version_info.major)");
		String pythonMinorVersionNum = runPythonCommand("-c",
				"import sys; print(sys.version_info.minor)");
		if (StringUtils.isBlank(pythonMajorVersionNum)
				|| StringUtils.isBlank(pythonMinorVersionNum)
				|| Integer.parseInt(pythonMajorVersionNum) < EXPECTED_PYTHON_VERSION_MAJOR
				|| Integer.parseInt(pythonMinorVersionNum) < EXPECTED_PYTHON_VERSION_MINOR) {
			throw new RuntimeException("Python Version minimum expected: "
					+ EXPECTED_PYTHON_VERSION_MAJOR + "." + EXPECTED_PYTHON_VERSION_MINOR
					+ " but got " + pythonMajorVersionNum + "." + pythonMinorVersionNum);
		}

		String pipVersion = runPipCommand("-V");
		if (StringUtils.isBlank(pipVersion)) {
			throw new RuntimeException("Pip is not installed");
		}
	}

	private void installCheckov() throws IOException {
		runPipCommand("install", "-Iv", "checkov==" + EXPECTED_CHECKOV_VERSION, "--force-reinstall",
				"-q", "--user", "--no-warn-script-location");

		String checkovVersionNum = runCheckovCommand("-v");
		if (StringUtils.isBlank(checkovVersionNum)
				|| !checkovVersionNum.startsWith(EXPECTED_CHECKOV_VERSION)) {
			throw new RuntimeException("Checkov Version Number is incorrect. Expected: "
					+ EXPECTED_CHECKOV_VERSION + " but received " + checkovVersionNum);
		}
	}

	private String runPythonCommand(String... command) throws IOException {
		List<String> commandString = new ArrayList<>();
		commandString.add("python3");
		commandString.addAll(Arrays.asList(command));
		return runCommand(commandString);
	}

	private String runPipCommand(String... command) throws IOException {
		List<String> commandString = new ArrayList<>();
		commandString.add("pip3");
		commandString.addAll(Arrays.asList(command));
		return runCommand(commandString);
	}

	private String runCheckovCommand(String... command) throws IOException {
		List<String> commandString = new ArrayList<>();
		commandString
				.addAll(Arrays.asList("-c", "from checkov import main as checkov; checkov.run();"));
		commandString.addAll(Arrays.asList(command));
		return runPythonCommand(commandString.toArray(new String[]{}));
	}

	private String runCommand(List<String> commands) throws IOException {
		ProcessBuilder pb = new ProcessBuilder(commands);
		Process p = pb.start();
		String results = IOUtils.toString(p.getInputStream(), Charset.defaultCharset()).trim();
		String errors = IOUtils.toString(p.getErrorStream(), Charset.defaultCharset()).trim();
		if (StringUtils.isNotBlank(errors)) {
			LOG.error("Command failed. Command: "
					+ Strings.join(Arrays.asList(commands), ' ') + " errors: " + errors);
		}
		return results;
	}

	public Map<String, CheckovRuleDto> getCoreRules() {
		return coreRules;
	}

	private Map<String, CheckovRuleDto> populateCoreRules() throws IOException {
		String rules = runCheckovCommand("--list");
		kong.unirest.json.JSONObject guidelines =
				Unirest.get(BRIDGECREW_GUIDELINES).asJson()
						.getBody().getObject().getJSONObject("guidelines");
		Map<String, CheckovRuleDto> coreRules = new LinkedHashMap<>();
		Stream.of(rules.split("\\r?\\n")).skip(2).forEachOrdered(r -> {
			String[] ruleLine = r.split("\\|");
			if (ruleLine.length != 7) {
				return;
			}
			CheckovRuleDto rule = new CheckovRuleDto();
			rule.setCoreRule(true);
			rule.setAuthor("core");
			rule.setName(ruleLine[2].trim());
			rule.setCheckovType(ruleLine[3].trim());
			rule.setCheckovEntity(ruleLine[4].trim());
			rule.setMessage(ruleLine[5].trim());
			rule.setCheckovIac(ruleLine[6].trim());
			String url = guidelines.optString(rule.getName(), "#");
			rule.setExternalUrl(url);
			coreRules.put(rule.getName(), rule);
		});
		return coreRules;
	}

	/**
	 * Execute a checkov scan on a directory, given the supplied checkov rules. This is equivalent
	 * to the checkov command line: <br>
	 * <code>
	 * checkov.py -d {targetDirectory} --quiet -o json -c {ruleChecks}
	 * </code>
	 * 
	 * @param targetDirectory the directory to scan
	 * @param ruleChecks      the checks to use
	 * @return a json object of the result from checkov
	 */
	public JsonObject runCheckovDirectoryScan(Path targetDirectory,
			List<CheckovRuleDto> ruleChecks) {
		String results;
		JsonObject json = new JsonObject();
		try {
			results = runCheckovCommand("-d", targetDirectory.toString(), "--quiet", "--no-guide",
					"-o", "json", "-c", ruleChecks.stream().map(CheckovRuleDto::getName)
							.collect(Collectors.joining(",")));
			json = gson.fromJson(results, JsonObject.class);
		} catch (Exception e) {
			json.addProperty("errors", e.getMessage());
		}

		return json;
	}

}
