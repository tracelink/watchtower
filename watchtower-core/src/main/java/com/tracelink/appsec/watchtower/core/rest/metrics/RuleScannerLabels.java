package com.tracelink.appsec.watchtower.core.rest.metrics;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.scan.presentation.ScannerIdentity;

import net.minidev.json.JSONObject;

/**
 * Adds a readable rule name and its scanner to each "findings by rule" label, so dashboards can
 * show "private-key" with the Betterleaks icon instead of "Betterleaks: private-key". A label is
 * matched to its scanner by a known scanner prefix or by the rule's module; a rule that no longer
 * exists gets no scanner rather than a guessed one.
 */
final class RuleScannerLabels {

	private static final String PREFIX_SEPARATOR = ": ";

	private RuleScannerLabels() {
	}

	/** A copy of {@code metrics} with parallel "names" and "scanners" lists; the input is not changed. */
	static JSONObject label(JSONObject metrics, RuleService rules) {
		List<String> labels = labels(metrics);
		Map<String, ScannerIdentity> byRule = scannersOfRules(labels, rules);
		List<String> names = new ArrayList<>(labels.size());
		List<Map<String, String>> scanners = new ArrayList<>(labels.size());
		for (String label : labels) {
			Optional<ScannerIdentity> prefixed = prefixScanner(label);
			names.add(prefixed.map(scanner -> label.substring(label.indexOf(PREFIX_SEPARATOR) + 2)).orElse(label));
			ScannerIdentity scanner = prefixed.orElse(byRule.get(label));
			scanners.add(scanner == null ? null : Map.of("name", scanner.name(), "icon", scanner.icon()));
		}
		JSONObject labelled = new JSONObject(metrics);
		labelled.put("names", Collections.unmodifiableList(names));
		labelled.put("scanners", Collections.unmodifiableList(scanners));
		return labelled;
	}

	private static List<String> labels(JSONObject metrics) {
		Object raw = metrics.get("labels");
		if (!(raw instanceof List<?> list)) {
			return List.of();
		}
		return list.stream().map(String::valueOf).toList();
	}

	private static Optional<ScannerIdentity> prefixScanner(String label) {
		int separator = label.indexOf(PREFIX_SEPARATOR);
		return separator > 0 ? ScannerIdentity.known(label.substring(0, separator)) : Optional.empty();
	}

	private static Map<String, ScannerIdentity> scannersOfRules(List<String> labels, RuleService rules) {
		Map<String, ScannerIdentity> byRule = new HashMap<>();
		if (labels.isEmpty() || rules == null) {
			return byRule;
		}
		for (RuleEntity rule : rules.getRulesByNames(labels)) {
			String module = rule.toDto() == null ? null : rule.toDto().getModule();
			if (module != null) {
				byRule.put(rule.getName(), ScannerIdentity.of(module));
			}
		}
		return byRule;
	}
}
