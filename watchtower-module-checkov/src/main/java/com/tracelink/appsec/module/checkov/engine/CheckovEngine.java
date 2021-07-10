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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
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

	private static final String BRIDGECREW_GUIDELINES =
			"https://www.bridgecrew.cloud/api/v1/guidelines";

	private static final int EXPECTED_PYTHON_VERSION_MAJOR = 3;
	private static final int EXPECTED_PYTHON_VERSION_MINOR = 7;

	private static final String EXPECTED_CHECKOV_VERSION = "2.0.257";

	private final Map<String, CheckovRuleDto> coreRules;

	private final Gson gson;

	public CheckovEngine() {
		gson = new Gson();
		try {
			testPythonVersion();
			LOG.info("Python installed correctly");
			installCheckov();
			LOG.info("Checkov installed correctly");
			coreRules = Collections.unmodifiableMap(populateCoreRules());
		} catch (Exception e) {
			throw new RuntimeException("Failed to create Checkov Engine", e);
		}
	}

	private void testPythonVersion() throws IOException {
		ProcessResult pythonMajorVersionNum = runPythonCommand("-c",
				"import sys; print(sys.version_info.major)");
		ProcessResult pythonMinorVersionNum = runPythonCommand("-c",
				"import sys; print(sys.version_info.minor)");
		if (pythonMajorVersionNum.hasErrors()) {
			LOG.error("Error during python version command: " + pythonMajorVersionNum.getErrors());
		}
		// major and minor should exist,
		// major is over the minimum expected or
		// major is the expected and minor is at least the expected
		if (!pythonMajorVersionNum.hasResults()
				|| !pythonMinorVersionNum.hasResults()
				|| Integer.parseInt(
						pythonMajorVersionNum.getResults()) < EXPECTED_PYTHON_VERSION_MAJOR
				|| (Integer.parseInt(
						pythonMajorVersionNum.getResults()) == EXPECTED_PYTHON_VERSION_MAJOR
						&& Integer.parseInt(pythonMinorVersionNum
								.getResults()) <= EXPECTED_PYTHON_VERSION_MINOR)) {
			throw new RuntimeException("Python Version minimum expected: "
					+ EXPECTED_PYTHON_VERSION_MAJOR + "." + EXPECTED_PYTHON_VERSION_MINOR
					+ " but got " + pythonMajorVersionNum + "." + pythonMinorVersionNum);
		}

		ProcessResult pipVersionResults = runPipCommand("-V");
		if (!pipVersionResults.hasResults()) {
			throw new RuntimeException("Pip is not installed");
		}
	}

	private void installCheckov() throws IOException {
		LOG.info("Testing for existing Checkov install");
		ProcessResult checkovVersionNumResult = runCheckovCommand("-v");
		if (checkovVersionNumResult.hasResults()
				&& checkovVersionNumResult.getResults().startsWith(EXPECTED_CHECKOV_VERSION)) {
			LOG.info("Checkov already installed at version " + EXPECTED_CHECKOV_VERSION);
			return;
		}

		LOG.info("Installing Checkov for virtual environment");
		ProcessResult pipResult = runPipCommand("install", "checkov==" + EXPECTED_CHECKOV_VERSION,
				"--force-reinstall", "--no-cache-dir", "--no-warn-script-location");

		if (pipResult.hasErrors()) {
			LOG.warn("Error during virtualenv pip install: " + pipResult.getErrors());
		}
		LOG.info(pipResult.getResults());
		checkovVersionNumResult = runCheckovCommand("-v");
		if (checkovVersionNumResult.hasResults()
				&& checkovVersionNumResult.getResults().startsWith(EXPECTED_CHECKOV_VERSION)) {
			// successfully installed in a virtual env or global scope
			LOG.info("Checkov installed in the virtual environment or global scope");
			return;
		}

		LOG.info("Not in virtual environment. Installing Checkov for user environment");
		pipResult = runPipCommand("install", "checkov==" + EXPECTED_CHECKOV_VERSION,
				"--force-reinstall", "--user", "--no-cache-dir", "--no-warn-script-location");

		if (pipResult.hasErrors()) {
			LOG.warn("Error during user dir pip install: " + pipResult.getErrors());
		}

		checkovVersionNumResult = runCheckovCommand("-v");
		if (!checkovVersionNumResult.hasResults()
				|| !checkovVersionNumResult.getResults().startsWith(EXPECTED_CHECKOV_VERSION)) {
			throw new RuntimeException("Checkov Version Number is incorrect. Expected: "
					+ EXPECTED_CHECKOV_VERSION + " but received "
					+ checkovVersionNumResult.getResults());
		}
		LOG.info("Checkov installed in the user environment");

	}

	private ProcessResult runPythonCommand(String... command) throws IOException {
		List<String> commandString = new ArrayList<>();
		commandString.add("python3");
		commandString.addAll(Arrays.asList(command));
		return runCommand(commandString);
	}

	private ProcessResult runPipCommand(String... command) throws IOException {
		List<String> commandString = new ArrayList<>();
		commandString.add("pip3");
		commandString.addAll(Arrays.asList(command));
		return runCommand(commandString);
	}

	private ProcessResult runCheckovCommand(String... command) throws IOException {
		List<String> commandString = new ArrayList<>();
		commandString
				.addAll(Arrays.asList("-c", "from checkov import main as checkov; checkov.run();"));
		commandString.addAll(Arrays.asList(command));
		return runPythonCommand(commandString.toArray(new String[]{}));
	}

	private ProcessResult runCommand(List<String> commands) throws IOException {
		ProcessBuilder pb = new ProcessBuilder(commands);
		Process p = null;
		ProcessResult result;
		try {
			p = pb.start();
			String results = IOUtils.toString(p.getInputStream(), Charset.defaultCharset()).trim();
			String errors = IOUtils.toString(p.getErrorStream(), Charset.defaultCharset()).trim();
			result = new ProcessResult(String.join(" ", commands), results, errors);
			if (LOG.isDebugEnabled()) {
				LOG.debug(result.getFullOutput("\n"));
			}
		} finally {
			if (p != null) {
				p.destroy();
			}
		}
		return result;
	}

	public Map<String, CheckovRuleDto> getCoreRules() {
		return coreRules;
	}

	private Map<String, CheckovRuleDto> populateCoreRules() throws IOException {
		ProcessResult rulesResult = runCheckovCommand("--list");
		kong.unirest.json.JSONObject guidelines =
				Unirest.get(BRIDGECREW_GUIDELINES).asJson()
						.getBody().getObject().getJSONObject("guidelines");
		Map<String, CheckovRuleDto> coreRules = new LinkedHashMap<>();
		Stream.of(rulesResult.getResults().split("\\r?\\n")).skip(2).forEachOrdered(r -> {
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
	 * checkov.py -d {targetDirectory} --quiet --no-guide -o json -c {ruleChecks}
	 * </code>
	 * 
	 * @param targetDirectory the directory to scan
	 * @param ruleChecks      the checks to use
	 * @return a json object of the result from checkov
	 */
	public JsonObject runCheckovDirectoryScan(Path targetDirectory,
			List<CheckovRuleDto> ruleChecks) {
		ProcessResult results;
		JsonObject json = new JsonObject();
		try {
			results = runCheckovCommand("-d", targetDirectory.toString(), "--quiet", "--no-guide",
					"-o", "json", "-c", ruleChecks.stream().map(CheckovRuleDto::getName)
							.collect(Collectors.joining(",")));
			json = gson.fromJson(results.getResults(), JsonObject.class);
		} catch (Exception e) {
			json.addProperty("errors", e.getMessage());
		}

		return json;
	}

}
