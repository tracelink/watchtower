package com.tracelink.appsec.watchtower.core.scan.presentation;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResultViolation;

/**
 * What a pull request bypass covers, for the bypass dialog: one group per file (short name, full
 * path on hover) holding each covered rule once with its highest severity, plus a count per
 * severity for the coloured dots. Same rule-and-file identity as the stored bypass.
 */
public record BypassCoverage(int total, List<FileGroup> files, List<SeverityCount> severities) {

	public record FileGroup(String name, String path, List<Rule> rules) { }

	public record Rule(String name, int severityValue, String severity) { }

	public record SeverityCount(int severityValue, long count) { }

	public static BypassCoverage of(List<PRScanResultViolation> violations) {
		if (violations == null || violations.isEmpty()) {
			return new BypassCoverage(0, List.of(), List.of());
		}
		Map<String, Map<String, Rule>> byFile = new TreeMap<>();
		for (PRScanResultViolation violation : violations) {
			String path = violation.getFileName() == null ? "" : violation.getFileName();
			Map<String, Rule> rules = byFile.computeIfAbsent(path, key -> new LinkedHashMap<>());
			Rule found = new Rule(violation.getViolationName(), violation.getSeverityValue(), violation.getSeverity());
			rules.merge(found.name(), found, (a, b) -> a.severityValue() <= b.severityValue() ? a : b);
		}
		List<FileGroup> files = new ArrayList<>();
		Map<Integer, Long> counts = new TreeMap<>();
		byFile.forEach((path, rules) -> {
			List<Rule> sorted = rules.values().stream()
					.sorted(Comparator.comparingInt(Rule::severityValue).thenComparing(Rule::name)).toList();
			sorted.forEach(rule -> counts.merge(rule.severityValue(), 1L, Long::sum));
			files.add(new FileGroup(path.substring(path.lastIndexOf('/') + 1), path, sorted));
		});
		int total = files.stream().mapToInt(group -> group.rules().size()).sum();
		List<SeverityCount> severities = counts.entrySet().stream()
				.map(entry -> new SeverityCount(entry.getKey(), entry.getValue())).toList();
		return new BypassCoverage(total, List.copyOf(files), severities);
	}
}
