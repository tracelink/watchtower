package com.tracelink.appsec.watchtower.core.scan.code;

import java.util.Collection;
import java.util.List;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.rule.RuleExecutionIdentity;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleRevision;
import com.tracelink.appsec.watchtower.core.rule.RuleState;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary;

/** Source-free selected definitions and explicit coverage; selected is never synonymous with ran. */
public record CodeScanExecutionSnapshot(int schema, Long rulesetId, String rulesetName,
		RulePriority blockingLevel, List<SelectedRule> rules, List<EngineExecution> engines,
		Long reusedFromScanId) {
	public static final int SCHEMA = 1;

	public CodeScanExecutionSnapshot {
		rules = rules == null ? List.of() : List.copyOf(rules);
		engines = engines == null ? List.of() : List.copyOf(engines);
	}

	public record SelectedRule(RuleExecutionIdentity identity, String name, RulePriority priority,
			RuleState state, String scanner, String coverage, Long evaluatedOpportunities) { }
	public record EngineExecution(String scanner, EngineExecutionIdentity identity,
			String status) {
		public EngineExecution {
			if (identity == null) identity = EngineExecutionIdentity.unknown(scanner);
		}
	}

	public static CodeScanExecutionSnapshot capture(RulesetDto ruleset,
			Collection<ICodeScanner> scanners, CodeScanConfig config) {
		List<SelectedRule> rules = ruleset.getAllRules().stream().map(rule -> {
			List<String> supported = scanners.stream().filter(scanner -> supports(scanner, rule.getClass()))
					.map(CodeScanExecutionSnapshot::scannerName).toList();
			String scannerName = supported.size() == 1 ? supported.getFirst() : null;
			return new SelectedRule(rule.getExecutionIdentity(), rule.getName(), rule.getPriority(),
					rule.getStewardship() == null ? null : rule.getStewardship().getState(), scannerName,
					supported.isEmpty() ? "UNSUPPORTED" : scanners.stream().filter(s -> supported.contains(scannerName(s))).allMatch(ICodeScanner::isDisabled) ? "DISABLED" : "UNKNOWN", null);
		}).toList();
		List<EngineExecution> engines = scanners.stream().filter(scanner ->
				ruleset.getAllRules().stream().anyMatch(rule -> supports(scanner, rule.getClass())))
				.map(scanner -> {
					EngineExecutionIdentity identity = scanner.getExecutionIdentity(config);
					return new EngineExecution(scannerName(scanner), identity == null
							? EngineExecutionIdentity.unknown(scannerName(scanner)) : identity, !scanner.isDisabled() ? "UNKNOWN" : "DISABLED");
				}).toList();
		return new CodeScanExecutionSnapshot(SCHEMA, ruleset.getId(), ruleset.getName(),
				ruleset.getBlockingLevel(), rules, engines, null);
	}

	private static boolean supports(ICodeScanner scanner, Class<?> ruleClass) {
		return scanner.getSupportedRuleClass() != null && scanner.getSupportedRuleClass().stream()
				.anyMatch(type -> type.isAssignableFrom(ruleClass));
	}

	public static String scannerName(ICodeScanner scanner) { return java.util.Objects.toString(scanner.executionName(),scanner.getClass().getName()); }

	/**
	 * Marks the named rules of one scanner as failed while the scanner itself stays as it was recorded, so a rule
	 * that could not run reads as that rule failing, not the whole scanner.
	 */
	public CodeScanExecutionSnapshot withFailedRules(ICodeScanner scanner, java.util.Collection<String> failedRuleNames) {
		String name = scannerName(scanner);
		if (failedRuleNames == null || failedRuleNames.isEmpty()
				|| engines.stream().filter(engine -> name.equals(engine.scanner())).count() > 1) return this;
		List<SelectedRule> updated = rules.stream().map(rule -> name.equals(rule.scanner()) && failedRuleNames.contains(rule.name())
				? new SelectedRule(rule.identity(), rule.name(), rule.priority(), rule.state(), name, "FAILED", null) : rule).toList();
		return new CodeScanExecutionSnapshot(schema, rulesetId, rulesetName, blockingLevel, updated, engines, null);
	}

	public CodeScanExecutionSnapshot withOutcome(ICodeScanner scanner, String status) {
		String name = scannerName(scanner);
		// Two configured instances of one class cannot be joined to an invocation by class name.
		if (engines.stream().filter(engine -> name.equals(engine.scanner())).count() > 1) return this;
		List<SelectedRule> updated = rules.stream().map(rule -> !name.equals(rule.scanner()) ? rule
				: new SelectedRule(rule.identity(), rule.name(), rule.priority(), rule.state(), name,
						List.of("SKIPPED", "DISABLED", "FAILED", "UNSUPPORTED", ScanExecutionSummary.NOT_APPLICABLE).contains(status) ? status : "UNKNOWN", null)).toList();
		return new CodeScanExecutionSnapshot(schema, rulesetId, rulesetName, blockingLevel, updated,
				engines.stream().map(engine -> name.equals(engine.scanner())
						? new EngineExecution(name, engine.identity(), status) : engine).toList(), null);
	}

	public CodeScanExecutionSnapshot reusedFrom(long scanId) {
		return new CodeScanExecutionSnapshot(schema, rulesetId, rulesetName, blockingLevel, rules,
				engines, scanId);
	}

	public String engineKey(String scanner) {
		List<EngineExecution> matching = engines.stream()
				.filter(engine -> Objects.equals(engine.scanner(), scanner)).toList();
		return matching.size() == 1 ? matching.getFirst().identity().fingerprint() : "unknown";
	}

	@JsonIgnore
	public boolean isReusable() {
		return schema == SCHEMA && rules.stream().allMatch(rule -> rule.scanner() != null
				&& rule.identity() != null && rule.identity().revision() != null
				&& rule.state() != null && rule.priority() != null
				&& engines.stream().anyMatch(engine -> rule.scanner().equals(engine.scanner())))
				&& engines.stream().allMatch(engine -> engine.scanner() != null && engine.identity().isReusable()
						&& ("UNKNOWN".equals(engine.status()) || completed(engine.status())));
	}

	/** A completed report must prove module success; preview snapshots have UNKNOWN status. */
	@JsonIgnore
	public boolean hasSuccessfulExecution() {
		return isReusable()
				&& engines.stream().allMatch(engine -> completed(engine.status()));
	}

	/** An engine that ran, or had no file of its types to look at, has finished its part of the scan. */
	public static boolean completed(String status) {
		return "RAN".equals(status) || ScanExecutionSummary.NOT_APPLICABLE.equals(status);
	}

	/** Names remain display attributes for managed rules; policy and lifecycle are separate. */
	public String fingerprint() {
		List<String> ruleKeys = rules.stream().map(rule -> {
			RuleExecutionIdentity identity = rule.identity();
			return RuleRevision.definition("execution-rule", "v1")
					.field("id", identity == null || identity.ruleId() == null ? null : identity.ruleId().toString())
					.field("ruleModule", identity == null ? null : identity.module())
					.field("revision", identity == null ? null : identity.revision())
					.field("externalKey", identity == null ? null : identity.externalRuleKey())
					.field("origin", identity == null ? null : identity.originKey())
					.field("name", rule.name()).field("priority", rule.priority() == null ? null : rule.priority().name())
					.field("state", rule.state() == null ? null : rule.state().name())
					.field("scanner", rule.scanner()).hash();
		}).toList();
		return RuleRevision.definition("ruleset-execution", "v2")
				.field("rulesetId", rulesetId == null ? null : rulesetId.toString())
				.field("rulesetName", rulesetName)
				.field("blockingLevel", blockingLevel == null ? null : blockingLevel.name())
				.unordered("rules", ruleKeys).unordered("engines", engines.stream()
						.map(engine -> engine.identity().fingerprint()).toList()).hash().substring(0, 32);
	}
}
