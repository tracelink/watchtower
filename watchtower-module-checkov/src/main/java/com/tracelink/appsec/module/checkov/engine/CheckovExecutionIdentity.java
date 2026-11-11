package com.tracelink.appsec.module.checkov.engine;

import java.util.List;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import com.google.gson.Gson;
import com.tracelink.appsec.module.checkov.model.CheckovProvidedRuleDto;
import com.tracelink.appsec.module.checkov.scanner.CheckovScanner;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.rule.RuleRevision;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.EngineExecutionIdentity;
import com.tracelink.appsec.watchtower.core.scan.code.JavaEngineExecutionIdentity;

/** Partial evidence: Python artifacts, private configuration and external inputs remain uncertified. */
final class CheckovExecutionIdentity {
	private record RuntimeEvidence(String python, String checkov, List<String> checks) {}

	private CheckovExecutionIdentity() {}

	static EngineExecutionIdentity capture(CheckovEngine engine, ICodeScanner scanner, CodeScanConfig config) {
		try {
			if (engine.getClass() != CheckovEngine.class || scanner.getClass() != CheckovScanner.class
					|| config.getRuleset() == null) return EngineExecutionIdentity.unknown("checkov");
			var result = engine.captureRuntime();
			if (!CheckovEngine.isComplete(result)) return EngineExecutionIdentity.unknown("checkov");
			var runtime = new Gson().fromJson(result.stdout(), RuntimeEvidence.class);
			if (runtime == null || runtime.python() == null || !runtime.python().matches("[0-9]+\\.[0-9]+\\.[0-9]+")
					|| runtime.checkov() == null || !runtime.checkov().matches("[0-9]+\\.[0-9]+\\.[0-9]+")
					|| runtime.checks() == null) return EngineExecutionIdentity.unknown("checkov");
			var selected = config.getRuleset().getAllRules().stream().filter(CheckovProvidedRuleDto.class::isInstance)
					.map(rule -> rule.getName()).toList();
			if (selected.isEmpty() || !runtime.checks().containsAll(selected)) return EngineExecutionIdentity.unknown("checkov");
			var javaEvidence = JavaEngineExecutionIdentity.capture("checkov", scanner, config,
					CheckovScanner.class, ICodeScanner.class, Gson.class, IOUtils.class, StringUtils.class);
			if (!javaEvidence.isReusable()) return javaEvidence;
			String configuration = RuleRevision.definition("checkov", "partial-execution-v1")
					.field("java", javaEvidence.configurationHash())
					.unordered("arguments", CheckovEngine.SCAN_ARGUMENTS).unordered("selectors", selected).hash();
			return new EngineExecutionIdentity("checkov", "python:" + runtime.python() + "/checkov:"
					+ runtime.checkov() + "/java:" + javaEvidence.version(), configuration, false);
		} catch (RuntimeException | LinkageError exception) {
			return EngineExecutionIdentity.unknown("checkov");
		}
	}
}
