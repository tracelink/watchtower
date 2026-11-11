package com.tracelink.appsec.module.betterleaks.scanner;

import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tracelink.appsec.module.betterleaks.allowlist.BetterleaksAllowlistEntry;
import com.tracelink.appsec.module.betterleaks.allowlist.BetterleaksAllowlistProvider;
import com.tracelink.appsec.module.betterleaks.engine.BetterleaksEngine;
import com.tracelink.appsec.module.betterleaks.engine.BetterleaksFinding;
import com.tracelink.appsec.module.betterleaks.engine.BetterleaksScanException;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksProvidedRuleDto;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksRuleDto;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanError;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanViolation;

import io.micrometer.core.instrument.MeterRegistry;

/**
 * {@link ICodeScanner} for Betterleaks. Findings carry the rule's guidance and location, never the
 * secret. The allowlist is applied per scan: rule-only entries leave their rule out, path entries
 * go into the engine's config. A failed scan fails open with a "scan incomplete" error, like any
 * other scanner error.
 *
 * @author Watchtower
 */
public class BetterleaksScanner implements ICodeScanner {

	private static final Logger LOG = LoggerFactory.getLogger(BetterleaksScanner.class);

	static final String DURATION_METRIC = "watchtower.betterleaks.scan.duration";

	static final String FAILURES_METRIC = "watchtower.betterleaks.scan.failures";

	static final String FINDINGS_METRIC = "watchtower.betterleaks.findings";

	/**
	 * Test code is scanned - fixtures are a common home for a real key. Installed dependencies
	 * are not; Betterleaks' own default config skips them too.
	 */
	private static final Set<String> EXCLUDED_FOLDERS = Set.of("node_modules");

	private final BetterleaksEngine engine;

	private final BetterleaksAllowlistProvider allowlistProvider;

	private final MeterRegistry meterRegistry;

	public BetterleaksScanner(BetterleaksEngine engine) {
		this(engine, BetterleaksAllowlistProvider.NONE, null);
	}

	/**
	 * @param engine            runs the binary
	 * @param allowlistProvider the allowlist to apply
	 * @param meterRegistry     where to record metrics, or null for none
	 */
	public BetterleaksScanner(BetterleaksEngine engine,
			BetterleaksAllowlistProvider allowlistProvider, MeterRegistry meterRegistry) {
		this.engine = engine;
		this.allowlistProvider = allowlistProvider;
		this.meterRegistry = meterRegistry;
	}

	@Override
	public com.tracelink.appsec.watchtower.core.scan.code.EngineExecutionIdentity getExecutionIdentity(
			CodeScanConfig config) {
		try {
			return engine.getExecutionIdentity(this, config,
					allowlistProvider.activeEntries(config.getRepositoryName()));
		} catch (RuntimeException exception) {
			return com.tracelink.appsec.watchtower.core.scan.code.EngineExecutionIdentity.unknown("betterleaks");
		}
	}

	@Override
	public CodeScanReport scan(CodeScanConfig config) {
		CodeScanReport report = new CodeScanReport();
		Map<String, BetterleaksRuleDto> rulesById = config.getRuleset().getAllRules()
				.stream()
				.filter(BetterleaksRuleDto.class::isInstance)
				.map(BetterleaksRuleDto.class::cast)
				.collect(Collectors.toMap(BetterleaksRuleDto::getBetterleaksId,
						Function.identity(), (first, duplicate) -> first));
		if (rulesById.isEmpty()) {
			return report;
		}
		long startedNanos = System.nanoTime();
		try {
			List<BetterleaksAllowlistEntry> allowlist =
					allowlistProvider.activeEntries(config.getRepositoryName());
			Set<String> enabledRuleIds = enabledRuleIds(rulesById.keySet(), allowlist);
			if (enabledRuleIds.isEmpty()) {
				return report;
			}
			List<BetterleaksAllowlistEntry> pathEntries =
					allowlist.stream().filter(entry -> entry.pathGlob() != null).toList();
			Path workingDirectory = config.getWorkingDirectory();
			List<BetterleaksCustomRuleDto> customRules = enabledRuleIds.stream()
					.map(rulesById::get)
					.filter(BetterleaksCustomRuleDto.class::isInstance)
					.map(BetterleaksCustomRuleDto.class::cast)
					.toList();
			for (BetterleaksFinding finding : engine.scan(workingDirectory, enabledRuleIds,
					pathEntries, customRules)) {
				addFinding(report, rulesById.get(finding.ruleId()), finding, workingDirectory);
			}
			recordDuration("success", startedNanos);
		} catch (BetterleaksScanException e) {
			fail(report, e.getReason().name(), e.getMessage(), startedNanos);
		} catch (RuntimeException e) {
			// e.g. the allowlist could not be read; never let it fail the whole PR scan.
			LOG.error("Betterleaks scan could not start", e);
			fail(report, BetterleaksScanException.Reason.OTHER.name(),
					"the scan could not be prepared", startedNanos);
		}
		return report;
	}

	private static Set<String> enabledRuleIds(Set<String> rulesetRuleIds,
			List<BetterleaksAllowlistEntry> allowlist) {
		Set<String> disabled = allowlist.stream()
				.filter(entry -> entry.pathGlob() == null && entry.ruleId() != null)
				.map(BetterleaksAllowlistEntry::ruleId)
				.collect(Collectors.toSet());
		Set<String> enabled = new TreeSet<>(rulesetRuleIds);
		enabled.removeAll(disabled);
		return enabled;
	}

	private void addFinding(CodeScanReport report, BetterleaksRuleDto rule,
			BetterleaksFinding finding, Path workingDirectory) {
		if (rule == null) {
			report.addError(new CodeScanError(
					"Betterleaks reported rule " + finding.ruleId() + ", which is not in the ruleset"));
			return;
		}
		Path file = workingDirectory.resolve(finding.file()).normalize();
		if (!file.startsWith(workingDirectory.normalize())) {
			// The path is not echoed: it came from the scanned tree.
			report.addError(new CodeScanError(
					"Betterleaks reported a file outside the scanned directory"));
			return;
		}
		CodeScanViolation violation = new CodeScanViolation();
		violation.setRuleIdentity(rule.getExecutionIdentity());
		violation.setViolationName(rule.getName());
		violation.setSeverity(rule.getPriority());
		violation.setFileName(file.toString());
		violation.setLineNum(finding.startLine());
		violation.setMessage(rule.getMessage());
		report.addViolation(violation);
		if (meterRegistry != null) {
			meterRegistry.counter(FINDINGS_METRIC, "rule", finding.ruleId()).increment();
		}
	}

	private void fail(CodeScanReport report, String reason, String message, long startedNanos) {
		LOG.warn("Betterleaks scan incomplete: {}", message);
		report.addError(new CodeScanError("Betterleaks scan incomplete: " + message));
		if (meterRegistry != null) {
			meterRegistry.counter(FAILURES_METRIC, "reason", reason.toLowerCase(Locale.ROOT))
					.increment();
		}
		recordDuration("failure", startedNanos);
	}

	private void recordDuration(String outcome, long startedNanos) {
		if (meterRegistry != null) {
			meterRegistry.timer(DURATION_METRIC, "outcome", outcome)
					.record(System.nanoTime() - startedNanos, TimeUnit.NANOSECONDS);
		}
	}

	@Override
	public List<Class<? extends RuleDto>> getSupportedRuleClass() {
		return List.of(BetterleaksProvidedRuleDto.class, BetterleaksCustomRuleDto.class);
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * Always true: the flagged line is the secret.
	 */
	@Override
	public boolean isSensitive() {
		return true;
	}

	@Override
	public Set<String> getExcludedFolders() {
		return EXCLUDED_FOLDERS;
	}
}
