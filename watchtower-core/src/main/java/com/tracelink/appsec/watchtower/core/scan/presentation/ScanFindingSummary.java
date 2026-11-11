package com.tracelink.appsec.watchtower.core.scan.presentation;

import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.SeverityCounts;

/** Saved per-scan counts, with each provider's imported findings included exactly once. */
public record ScanFindingSummary(long total, long providerCount,
		List<SeverityCountPresentationModel> severities, boolean providerIncomplete) {

	public static ScanFindingSummary of(SeverityCounts local, long localTotal,
			List<ProviderAssessmentReference> providers) {
		Map<RulePriority, Long> counts = new EnumMap<>(RulePriority.class);
		for (RulePriority priority : RulePriority.values()) {
			counts.put(priority, (long) local.get(priority));
		}
		return of(counts, localTotal, providers);
	}

	public static ScanFindingSummary of(Map<RulePriority, Long> local, long localTotal,
			List<ProviderAssessmentReference> providers) {
		Map<RulePriority, Long> counts = new EnumMap<>(RulePriority.class);
		long localClassified = 0;
		for (RulePriority priority : RulePriority.values()) {
			long amount = Math.max(0, local.getOrDefault(priority, 0L));
			counts.put(priority, amount);
			localClassified += amount;
		}
		long unclassified = Math.max(0, localTotal - localClassified);
		long providerTotal = 0;
		boolean incomplete = false;
		for (ProviderAssessmentReference provider : providers == null
				? List.<ProviderAssessmentReference>of() : providers) {
			if (provider.status() == null) {
				incomplete = true;
				continue;
			}
			int imported = Math.max(0, provider.status().imported());
			providerTotal += imported;
			incomplete |= !provider.status().complete();
			int remaining = imported;
			Map<String, Integer> nativeCounts = provider.status().nativeSeverityCounts();
			if (nativeCounts != null) {
				for (var entry : nativeCounts.entrySet()) {
					int amount = Math.min(remaining, Math.max(0, entry.getValue() == null ? 0 : entry.getValue()));
					RulePriority priority = nativePriority(entry.getKey());
					if (priority == null) unclassified += amount;
					else counts.merge(priority, (long) amount, Long::sum);
					remaining -= amount;
				}
			}
			unclassified += remaining;
		}
		return new ScanFindingSummary(localTotal + providerTotal, providerTotal,
				SeverityCountPresentationModel.fromTotals(counts, unclassified), incomplete);
	}

	private static RulePriority nativePriority(String name) {
		return switch (name == null ? "" : name.toUpperCase(Locale.ROOT).replace(' ', '_')) {
			case "CRITICAL", "HIGH" -> RulePriority.HIGH;
			case "MEDIUM_HIGH" -> RulePriority.MEDIUM_HIGH;
			case "MEDIUM" -> RulePriority.MEDIUM;
			case "MEDIUM_LOW" -> RulePriority.MEDIUM_LOW;
			case "LOW" -> RulePriority.LOW;
			case "INFORMATIONAL", "INFO" -> RulePriority.INFORMATIONAL;
			default -> null;
		};
	}
}
