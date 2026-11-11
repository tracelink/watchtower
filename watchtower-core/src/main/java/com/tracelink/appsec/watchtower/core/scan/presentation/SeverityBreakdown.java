package com.tracelink.appsec.watchtower.core.scan.presentation;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * One severity of a report's findings, for the coloured severity bar and its filter chips: the
 * filter key the findings workspace already uses, a label, the count and its share of the bar.
 */
public record SeverityBreakdown(String key, String label, long count, double percent) {

	/** Highest severity first, as the findings are listed; empty when there are no findings. */
	public static List<SeverityBreakdown> of(List<FindingPresentationModel> findings) {
		if (findings == null || findings.isEmpty()) {
			return List.of();
		}
		Map<String, long[]> counts = new LinkedHashMap<>();
		Map<String, String> labels = new LinkedHashMap<>();
		Map<String, Integer> order = new LinkedHashMap<>();
		for (FindingPresentationModel finding : findings) {
			String key = finding.getSeverityFilterKey();
			counts.computeIfAbsent(key, k -> new long[1])[0]++;
			labels.putIfAbsent(key, finding.getSeverity());
			order.putIfAbsent(key, "CRITICAL".equals(key) ? 0 : finding.getSeverityValue());
		}
		List<SeverityBreakdown> result = new ArrayList<>();
		counts.forEach((key, count) -> result.add(new SeverityBreakdown(key, labels.get(key), count[0],
				100.0 * count[0] / findings.size())));
		result.sort(java.util.Comparator.comparingInt(breakdown -> order.get(breakdown.key())));
		return List.copyOf(result);
	}

	/** One file's findings by severity, for its row in the report's code section. */
	public static List<SeverityBreakdown> forFile(List<FindingPresentationModel> findings, String fileName) {
		if (findings == null || fileName == null) {
			return List.of();
		}
		return of(findings.stream().filter(finding -> fileName.equals(finding.getFileName())).toList());
	}

	/** CSS width for the bar segment, e.g. "72.2%". */
	public String getWidth() {
		return String.format(java.util.Locale.ROOT, "%.1f%%", percent);
	}
}
