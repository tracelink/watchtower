package com.tracelink.appsec.module.betterleaks.engine;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tracelink.appsec.module.betterleaks.allowlist.BetterleaksAllowlistEntry;
import com.tracelink.appsec.module.betterleaks.engine.BetterleaksScanException.Reason;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto;
import com.tracelink.appsec.watchtower.core.process.ProcessExecutionException;
import com.tracelink.appsec.watchtower.core.process.ProcessRequest;
import com.tracelink.appsec.watchtower.core.process.ProcessResult;
import com.tracelink.appsec.watchtower.core.process.ProcessRunner;

/**
 * Runs the pinned Betterleaks binary over a directory and returns what it found - never what the
 * secret was. Every scan:
 * <ul>
 * <li>passes a Watchtower-owned config with {@code --config}, so a repository's own
 * {@code .betterleaks.toml}/{@code .gitleaks.toml} cannot allowlist anything;</li>
 * <li>deletes committed {@code .betterleaksignore}/{@code .gitleaksignore} files, which the binary
 * honours at the scan root even when {@code --gitleaks-ignore-path} points elsewhere;</li>
 * <li>ignores inline {@code betterleaks:allow}/{@code gitleaks:allow} comments;</li>
 * <li>redacts matches, so the report never contains the secret;</li>
 * <li>enables only the ruleset's rules, and is bounded in time and output.</li>
 * </ul>
 * The binary runs inside the scanned directory against {@code .}, so reported paths - and the
 * allowlist's anchored path patterns - are repository-relative. Flags are verified against
 * {@code BetterleaksModule#BETTERLEAKS_VERSION}; re-check them, with
 * {@code BetterleaksEngineBinaryTest}, when upgrading the binary.
 *
 * @author Watchtower
 */
public class BetterleaksEngine {

	private static final Logger LOG = LoggerFactory.getLogger(BetterleaksEngine.class);

	/** Environment variable naming the binary; {@link #DEFAULT_BINARY} on the PATH otherwise. */
	public static final String BINARY_PATH_ENV = "WATCHTOWER_BETTERLEAKS_PATH";

	static final String DEFAULT_BINARY = "betterleaks";

	static final Duration SCAN_TIMEOUT = Duration.ofMinutes(2);

	static final long MAX_OUTPUT_BYTES = 16L * 1024 * 1024;

	static final Duration RULE_TEST_TIMEOUT = Duration.ofSeconds(30);

	static final String POSITIVE_SAMPLE_FILE = "positive-sample.txt";

	static final String NEGATIVE_SAMPLE_FILE = "negative-sample.txt";

	private static final int MAX_DIAGNOSTIC_CHARS = 300;

	private static final java.util.regex.Pattern ANSI_COLOUR =
			java.util.regex.Pattern.compile("\u001B\\[[0-9;]*m");

	/** What 1.8.1 logs when a rule's CEL filter fails to evaluate. */
	private static final String FILTER_EVAL_ERROR = "filter eval error";

	/** What 1.8.1 logs when a rule's CEL filter does not compile. */
	private static final String FILTER_COMPILE_ERROR = "filter compile error";

	private static final Duration VERSION_TIMEOUT = Duration.ofSeconds(10);

	private static final long VERSION_OUTPUT_BYTES = 4096;

	private static final Set<String> BYPASS_FILE_NAMES =
			Set.of(".betterleaksignore", ".gitleaksignore");

	private static final Set<PosixFilePermission> OWNER_ONLY_DIRECTORY =
			PosixFilePermissions.fromString("rwx------");

	private static final Set<PosixFilePermission> OWNER_ONLY_FILE =
			PosixFilePermissions.fromString("rw-------");

	private final ProcessRunner runner;

	private final String binary;

	private final BetterleaksReportParser parser = new BetterleaksReportParser();

	public BetterleaksEngine() {
		this(new ProcessRunner(), resolveBinary(System.getenv()));
	}

	public BetterleaksEngine(ProcessRunner runner, String binary) {
		this.runner = runner;
		this.binary = binary;
	}

	/**
	 * @param environment the process environment
	 * @return the binary to run: {@link #BINARY_PATH_ENV} if set, else {@code betterleaks}
	 */
	public static String resolveBinary(Map<String, String> environment) {
		String configured = environment.get(BINARY_PATH_ENV);
		return StringUtils.isBlank(configured) ? DEFAULT_BINARY : configured.trim();
	}

	/**
	 * @return true if the binary runs; used to skip tests where it is not installed
	 */
	public boolean isAvailable() {
		try {
			return runner.run(new ProcessRequest(List.of(binary, "version"), null,
					VERSION_TIMEOUT, VERSION_OUTPUT_BYTES)).isSuccess();
		} catch (ProcessExecutionException e) {
			return false;
		}
	}

	/** Bounded runtime evidence; native dependencies/environment remain explicitly uncertified. */
	public com.tracelink.appsec.watchtower.core.scan.code.EngineExecutionIdentity getExecutionIdentity(
			com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner scanner,
			com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig config,
			List<BetterleaksAllowlistEntry> allowlist) {
		return BetterleaksExecutionIdentity.capture(this, scanner, config, allowlist);
	}

	ProcessResult captureVersion() throws ProcessExecutionException {
		return runner.run(new ProcessRequest(List.of(binary, "version"), null,
				VERSION_TIMEOUT, VERSION_OUTPUT_BYTES));
	}

	String binary() { return binary; }

	/**
	 * Scans a directory with the given rules and no allowlist.
	 *
	 * @see #scan(Path, Collection, Collection)
	 */
	public List<BetterleaksFinding> scan(Path target, Collection<String> ruleIds)
			throws BetterleaksScanException {
		return scan(target, ruleIds, List.of());
	}

	/**
	 * Scans a directory with the given rules.
	 *
	 * @param target    the directory to scan; committed ignore files in it are deleted
	 * @param ruleIds   the Betterleaks rule ids to enable
	 * @param allowlist active allowlist entries; path entries are rendered into the config
	 * @return the findings, with repository-relative paths and without the secrets; empty if no
	 *         rules were given
	 * @throws BetterleaksScanException if the scan failed, timed out, or its output could not be
	 *                                  trusted
	 */
	public List<BetterleaksFinding> scan(Path target, Collection<String> ruleIds,
			Collection<BetterleaksAllowlistEntry> allowlist) throws BetterleaksScanException {
		return scan(target, ruleIds, allowlist, List.of());
	}

	/**
	 * Scans a directory with the given rules.
	 *
	 * @param target      the directory to scan; committed ignore files in it are deleted
	 * @param ruleIds     the Betterleaks rule ids to enable, built-in or custom
	 * @param allowlist   active allowlist entries; path entries are rendered into the config
	 * @param customRules definitions of the custom rules among {@code ruleIds}
	 * @return the findings, with repository-relative paths and without the secrets; empty if no
	 *         rules were given
	 * @throws BetterleaksScanException if the scan failed, timed out, or its output could not be
	 *                                  trusted
	 */
	public List<BetterleaksFinding> scan(Path target, Collection<String> ruleIds,
			Collection<BetterleaksAllowlistEntry> allowlist,
			Collection<BetterleaksCustomRuleDto> customRules) throws BetterleaksScanException {
		if (ruleIds.isEmpty()) {
			return List.of();
		}
		validateRuleIds(ruleIds);
		String config = renderConfig(allowlist, customRules);
		try {
			removeBypassFiles(target);
		} catch (IOException e) {
			throw new BetterleaksScanException(Reason.PREPARATION,
					"could not prepare the betterleaks scan: " + e.getMessage());
		}
		ProcessResult result = execute(target, ruleIds, config, SCAN_TIMEOUT);
		checkSucceeded(result);
		List<BetterleaksFinding> findings = parser.parse(result.stdout());
		LOG.debug("betterleaks scanned {} rule(s) with {} allowlist entr(ies) in {} ms: {}"
				+ " finding(s)", ruleIds.size(), allowlist.size(), result.elapsed().toMillis(),
				findings.size());
		return findings;
	}

	/**
	 * Asks the provider whether the secrets one built-in rule finds in a directory still work,
	 * with the rule's own CEL {@code validate} block. Makes network calls - one bounded request
	 * per finding - so it runs only on request, never during a pull request scan. The secret stays
	 * redacted in the output.
	 *
	 * @param target a Watchtower-written directory holding only the text to check
	 * @param ruleId the built-in Betterleaks rule id
	 * @return the rule's findings in the directory, each with its validation status
	 * @throws BetterleaksScanException if the run failed or timed out
	 */
	public List<BetterleaksValidation> validate(Path target, String ruleId)
			throws BetterleaksScanException {
		validateRuleIds(List.of(ruleId));
		ProcessResult result = execute(target, List.of(ruleId),
				renderConfig(List.of(), List.of()), SCAN_TIMEOUT, true);
		checkSucceeded(result);
		return parser.parseValidations(result.stdout());
	}

	/**
	 * Runs a custom rule over its own samples, in a throwaway directory, to prove it compiles in
	 * the binary and matches what it should. The samples are the author's own text, so - unlike a
	 * scan - the binary's error line is shown to them to explain a rejected rule.
	 *
	 * @param rule the rule to test
	 * @return whether it matched each sample, or why it could not run
	 */
	public BetterleaksRuleTestResult testRule(BetterleaksCustomRuleDto rule) {
		List<String> problems = rule.fieldProblems();
		if (!problems.isEmpty()) {
			return BetterleaksRuleTestResult.problem(String.join(" ", problems));
		}
		Path sandbox = null;
		try {
			sandbox = Files.createTempDirectory("watchtower-betterleaks-test-",
					PosixFilePermissions.asFileAttribute(OWNER_ONLY_DIRECTORY));
			writeOwnerOnly(sandbox.resolve(POSITIVE_SAMPLE_FILE), rule.getPositiveSample());
			writeOwnerOnly(sandbox.resolve(NEGATIVE_SAMPLE_FILE), rule.getNegativeSample());
			ProcessResult result = execute(sandbox, Set.of(rule.getBetterleaksId()),
					BetterleaksConfigRenderer.render(List.of(), List.of(rule)), RULE_TEST_TIMEOUT);
			if (result.timedOut()) {
				return BetterleaksRuleTestResult.problem("Testing the rule timed out after "
						+ RULE_TEST_TIMEOUT.toSeconds() + "s; simplify the regex or filter.");
			}
			if (result.exitCode() != 0) {
				return BetterleaksRuleTestResult
						.problem("Betterleaks rejected the rule: " + firstError(result));
			}
			// A filter that fails to evaluate keeps the finding and only warns, silently turning
			// the filter into a no-op.
			// Likewise a filter that does not compile: 1.8.1 warns and keeps every finding.
			if (StringUtils.contains(result.stderr(), FILTER_COMPILE_ERROR)) {
				return BetterleaksRuleTestResult.problem("The filter failed to compile: "
						+ firstLineContaining(result.stderr(), FILTER_COMPILE_ERROR));
			}
			if (StringUtils.contains(result.stderr(), FILTER_EVAL_ERROR)) {
				return BetterleaksRuleTestResult.problem("The filter failed to evaluate: "
						+ firstLineContaining(result.stderr(), FILTER_EVAL_ERROR));
			}
			List<BetterleaksFinding> findings = parser.parse(result.stdout());
			return new BetterleaksRuleTestResult(foundIn(findings, POSITIVE_SAMPLE_FILE),
					foundIn(findings, NEGATIVE_SAMPLE_FILE), null);
		} catch (IOException | BetterleaksScanException e) {
			return BetterleaksRuleTestResult.problem("The rule could not be tested: "
					+ e.getMessage());
		} finally {
			if (sandbox != null) {
				FileUtils.deleteQuietly(sandbox.toFile());
			}
		}
	}

	private static boolean foundIn(List<BetterleaksFinding> findings, String fileName) {
		return findings.stream().anyMatch(finding -> finding.file().endsWith(fileName));
	}

	/** The binary's own fatal/error line, for a rule author only; never logged. */
	private static String firstError(ProcessResult result) {
		String line = firstLineContaining(result.stderr(), "FTL");
		if (line == null) {
			line = firstLineContaining(result.stderr(), "ERR");
		}
		return line == null ? "exit code " + result.exitCode() : line;
	}

	private static String firstLineContaining(String text, String needle) {
		return StringUtils.defaultString(text).lines()
				.filter(line -> line.contains(needle))
				.map(BetterleaksEngine::plainDiagnostic)
				.map(line -> StringUtils.abbreviate(line, MAX_DIAGNOSTIC_CHARS))
				.findFirst()
				.orElse(null);
	}

	/** One stderr line without terminal colour codes and without the "4:57PM FTL" log prefix. */
	static String plainDiagnostic(String line) {
		return ANSI_COLOUR.matcher(StringUtils.defaultString(line)).replaceAll("").strip()
				.replaceFirst("^\\S+\\s+(?:FTL|ERR|WRN|INF|DBG)\\s+", "");
	}

	/**
	 * Writes the config and an empty ignore file to an owner-only scratch directory outside the
	 * target (so neither is itself scanned) and runs the binary inside the target.
	 */
	private ProcessResult execute(Path target, Collection<String> ruleIds, String config,
			Duration timeout) throws BetterleaksScanException {
		return execute(target, ruleIds, config, timeout, false);
	}

	private ProcessResult execute(Path target, Collection<String> ruleIds, String config,
			Duration timeout, boolean validation) throws BetterleaksScanException {
		Path scratch = null;
		try {
			scratch = Files.createTempDirectory("watchtower-betterleaks-",
					PosixFilePermissions.asFileAttribute(OWNER_ONLY_DIRECTORY));
			Path configFile = writeOwnerOnly(scratch.resolve("config.toml"), config);
			Path ignoreFile = writeOwnerOnly(scratch.resolve("empty.betterleaksignore"), "");
			return run(new ProcessRequest(
					buildCommand(configFile, ignoreFile, ruleIds, validation), target, timeout,
					MAX_OUTPUT_BYTES));
		} catch (IOException e) {
			throw new BetterleaksScanException(Reason.PREPARATION,
					"could not prepare the betterleaks scan: " + e.getMessage());
		} finally {
			if (scratch != null) {
				FileUtils.deleteQuietly(scratch.toFile());
			}
		}
	}

	/**
	 * @param config  the Watchtower-owned config file
	 * @param ignore  an empty ignore file
	 * @param ruleIds the rule ids to enable
	 * @return the full command line; it scans {@code .}, the process's working directory
	 */
	List<String> buildCommand(Path config, Path ignore, Collection<String> ruleIds) {
		return buildCommand(config, ignore, ruleIds, false);
	}

	/**
	 * @param validation whether to ask providers if the found secrets work; one worker and one
	 *                   request per provider target keep a check from turning into a burst
	 * @see #buildCommand(Path, Path, Collection)
	 */
	List<String> buildCommand(Path config, Path ignore, Collection<String> ruleIds,
			boolean validation) {
		List<String> command = new ArrayList<>(List.of(binary, "dir",
				"--no-banner", "--no-color", "--log-level", "warn",
				"--config", config.toString(),
				"--gitleaks-ignore-path", ignore.toString(),
				"--ignore-gitleaks-allow",
				"--redact",
				// Findings exit 0 too, so any non-zero exit is a real failure.
				"--exit-code", "0",
				"--report-format", "json", "--report-path", "-",
				"--enable-rule", ruleIds.stream().sorted().collect(Collectors.joining(","))));
		if (validation) {
			command.addAll(List.of("--validation", "--validation-timeout", "10s",
					"--validation-workers", "1", "--validation-max-requests", "1"));
		}
		command.add(".");
		return command;
	}

	private static String renderConfig(Collection<BetterleaksAllowlistEntry> allowlist,
			Collection<BetterleaksCustomRuleDto> customRules) throws BetterleaksScanException {
		try {
			return BetterleaksConfigRenderer.render(allowlist, customRules);
		} catch (IllegalArgumentException e) {
			throw new BetterleaksScanException(Reason.PREPARATION,
					"invalid config: " + e.getMessage());
		}
	}

	private static void validateRuleIds(Collection<String> ruleIds)
			throws BetterleaksScanException {
		for (String ruleId : ruleIds) {
			if (!BetterleaksRuleIds.isValid(ruleId)) {
				throw new BetterleaksScanException(Reason.INVALID_RULE,
						"invalid betterleaks rule id: " + ruleId);
			}
		}
	}

	private static void removeBypassFiles(Path target) throws IOException {
		try (Stream<Path> paths = Files.walk(target)) {
			List<Path> bypassFiles = paths
					.filter(path -> BYPASS_FILE_NAMES.contains(String.valueOf(path.getFileName())))
					.filter(Files::isRegularFile)
					.toList();
			for (Path bypassFile : bypassFiles) {
				Files.delete(bypassFile);
				LOG.info("Removed committed {} before the betterleaks scan",
						bypassFile.getFileName());
			}
		}
	}

	private static Path writeOwnerOnly(Path file, String content) throws IOException {
		Files.createFile(file, PosixFilePermissions.asFileAttribute(OWNER_ONLY_FILE));
		return Files.writeString(file, content);
	}

	private ProcessResult run(ProcessRequest request) throws BetterleaksScanException {
		try {
			return runner.run(request);
		} catch (ProcessExecutionException e) {
			throw new BetterleaksScanException(Reason.START_FAILURE,
					"could not run betterleaks: " + e.getMessage());
		}
	}

	private static void checkSucceeded(ProcessResult result) throws BetterleaksScanException {
		if (result.timedOut()) {
			throw new BetterleaksScanException(Reason.TIMEOUT,
					"betterleaks timed out after " + SCAN_TIMEOUT.toSeconds() + "s");
		}
		if (result.stdoutTruncated()) {
			throw new BetterleaksScanException(Reason.OUTPUT_LIMIT,
					"betterleaks output exceeded the " + MAX_OUTPUT_BYTES / (1024 * 1024)
							+ " MB output limit");
		}
		if (result.exitCode() != 0) {
			// Never the stderr content: Betterleaks redacts its own logs, but Watchtower must not
			// rely on that. Reproduce locally with the logged exit code to see the detail.
			LOG.warn("betterleaks failed with exit code {} ({} chars of stderr withheld)",
					result.exitCode(), StringUtils.length(result.stderr()));
			throw new BetterleaksScanException(Reason.EXIT_CODE,
					"betterleaks failed with exit code " + result.exitCode());
		}
	}
}
