package com.tracelink.appsec.module.eslint.engine;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import com.google.gson.Gson;
import com.samskivert.mustache.Mustache;
import com.tracelink.appsec.module.eslint.interpreter.EsLintRulesetExporter;
import com.tracelink.appsec.module.eslint.model.EsLintCustomRuleDto;
import com.tracelink.appsec.module.eslint.model.EsLintProvidedRuleDto;
import com.tracelink.appsec.module.eslint.scanner.EsLintScanner;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.rule.RuleRevision;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.EngineExecutionIdentity;
import com.tracelink.appsec.watchtower.core.scan.code.JavaEngineExecutionIdentity;

/** Runtime and bridge evidence for provided ESLint rules; arbitrary JavaScript stays unknown. */
final class EsLintExecutionIdentity {

	private static final String ENGINE = "eslint";
	private record RuntimeEvidence(int schema, boolean complete, String nodeVersion,
			String eslintVersion, String fingerprint, List<String> rules, List<String> selected) {}

	private EsLintExecutionIdentity() {}

	static EngineExecutionIdentity capture(LinterEngine engine, ICodeScanner scanner, CodeScanConfig config) {
		try {
			if (scanner.getClass() != EsLintScanner.class || config.getRuleset() == null
					|| config.getRuleset().getAllRules().stream().anyMatch(EsLintCustomRuleDto.class::isInstance)) {
				return EngineExecutionIdentity.unknown(ENGINE);
			}
			var implementation = RuleRevision.definition(ENGINE, "implementation-v1");
			var directory = engine.getWorkingDirectory();
			if (!directory.toRealPath().equals(directory.normalize())) return EngineExecutionIdentity.unknown(ENGINE);
			for (String name : List.of("linter_scan.js", "linter_parse.js", "linter_identity.js")) {
				var file = directory.resolve(name);
				String expected = resourceHash("js/" + name);
				if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)
						|| !expected.equals(hash(Files.readAllBytes(file)))) return EngineExecutionIdentity.unknown(ENGINE);
				implementation.field(name, expected);
			}
			String selection;
			try (var exported = new EsLintRulesetExporter().exportRuleset(config.getRuleset())) {
				if (exported == null) return EngineExecutionIdentity.unknown(ENGINE);
				selection = new String(exported.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
			}
			var result = engine.captureRuntime(selection);
			if (result.hasErrors() || !result.hasResults()) return EngineExecutionIdentity.unknown(ENGINE);
			var runtime = new Gson().fromJson(result.getResults(), RuntimeEvidence.class);
			if (runtime == null || runtime.schema() != 1 || !runtime.complete() || runtime.rules() == null || runtime.selected() == null
					|| runtime.nodeVersion() == null || !runtime.nodeVersion().matches("v[0-9]+\\.[0-9]+\\.[0-9]+")
					|| runtime.eslintVersion() == null || !runtime.eslintVersion().matches("[0-9]+\\.[0-9]+\\.[0-9]+")
					|| runtime.fingerprint() == null || !runtime.fingerprint().matches("[0-9a-f]{64}")) {
				return EngineExecutionIdentity.unknown(ENGINE);
			}
			var selected = config.getRuleset().getAllRules().stream()
					.filter(EsLintProvidedRuleDto.class::isInstance).map(rule -> rule.getName()).toList();
			if (!runtime.rules().containsAll(selected) || runtime.selected().size() != selected.size()
					|| !runtime.selected().containsAll(selected)) return EngineExecutionIdentity.unknown(ENGINE);
			var javaEvidence = JavaEngineExecutionIdentity.capture(ENGINE, scanner, config, EsLintScanner.class,
					ICodeScanner.class, Gson.class, Mustache.class, IOUtils.class, StringUtils.class);
			if (!javaEvidence.isReusable()) return javaEvidence;
			String artifacts = implementation.field("java", javaEvidence.version()).field("node", runtime.fingerprint())
					.field("exportTemplate", resourceHash("templates/export/ruleset.js")).hash();
			// The exporter/bridge's actual rule order can affect message ordering.
			var settings = RuleRevision.definition(ENGINE, "execution-v1")
					.field("artifacts", artifacts).field("java", javaEvidence.configurationHash());
			for (int index = 0; index < runtime.selected().size(); index++) {
				settings.field("rule-" + index, runtime.selected().get(index));
			}
			String configuration = settings.hash();
			return new EngineExecutionIdentity(ENGINE, "node:" + runtime.nodeVersion() + "/eslint:"
					+ runtime.eslintVersion() + "/sha256:" + artifacts, configuration, true);
		} catch (Exception | LinkageError exception) {
			return EngineExecutionIdentity.unknown(ENGINE);
		}
	}

	private static String resourceHash(String name) throws IOException {
		try (var input = LinterEngine.class.getClassLoader().getResourceAsStream(name)) {
			if (input == null) throw new IOException("Missing engine resource");
			return hash(input.readAllBytes());
		}
	}

	private static String hash(byte[] bytes) {
		try {
			return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes));
		} catch (java.security.NoSuchAlgorithmException exception) {
			throw new IllegalStateException(exception);
		}
	}
}
