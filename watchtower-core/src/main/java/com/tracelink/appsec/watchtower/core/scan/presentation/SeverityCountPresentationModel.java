package com.tracelink.appsec.watchtower.core.scan.presentation;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.SeverityCounts;

/** Compact, accessible severity count used by scan-summary tables. */
public final class SeverityCountPresentationModel {
	private final int severityValue;
	private final long count;
	private final String compactText;
	private final String accessibleText;

	private SeverityCountPresentationModel(RulePriority priority, long count) {
		this.count = count;
		this.severityValue = priority.getPriority();
		this.compactText = count + abbreviation(priority);
		this.accessibleText = count + " " + priority.getName() + " "
				+ (count == 1 ? "finding" : "findings");
	}

	private SeverityCountPresentationModel(long unclassified) {
		this.count = unclassified;
		this.severityValue = 0;
		this.compactText = unclassified + " U";
		this.accessibleText = unclassified + " unclassified "
				+ (unclassified == 1 ? "finding" : "findings");
	}

	/** The neutral chip keeps an imported finding visible when its severity was not recorded. */
	public static List<SeverityCountPresentationModel> fromTotals(
			Map<RulePriority, Long> counts, long unclassified) {
		List<SeverityCountPresentationModel> result = new ArrayList<>();
		for (RulePriority priority : RulePriority.values()) {
			long count = counts.getOrDefault(priority, 0L);
			if (count > 0) result.add(new SeverityCountPresentationModel(priority, count));
		}
		if (unclassified > 0) result.add(new SeverityCountPresentationModel(unclassified));
		return List.copyOf(result);
	}

	public static List<SeverityCountPresentationModel> fromEntities(
			List<? extends AbstractScanViolationEntity<?>> violations) {
		if (violations == null || violations.isEmpty()) return List.of();
		Map<RulePriority, Long> counts = new EnumMap<>(RulePriority.class);
		for (AbstractScanViolationEntity<?> violation : violations) {
			RulePriority priority = violation.getSeverity() == null
					? RulePriority.INFORMATIONAL : violation.getSeverity();
			counts.merge(priority, 1L, Long::sum);
		}
		List<SeverityCountPresentationModel> result = new ArrayList<>();
		for (RulePriority priority : RulePriority.values()) {
			long count = counts.getOrDefault(priority, 0L);
			if (count > 0) result.add(new SeverityCountPresentationModel(priority, count));
		}
		return List.copyOf(result);
	}

	/** The same chips from counts stored on a scan row (repository scans keep no findings). */
	public static List<SeverityCountPresentationModel> fromCounts(SeverityCounts counts) {
		if (counts == null) return List.of();
		List<SeverityCountPresentationModel> result = new ArrayList<>();
		for (RulePriority priority : RulePriority.values()) {
			long count = counts.get(priority);
			if (count > 0) result.add(new SeverityCountPresentationModel(priority, count));
		}
		return List.copyOf(result);
	}

	private static String abbreviation(RulePriority priority) {
		return switch (priority) {
			case HIGH -> "H";
			case MEDIUM_HIGH -> "MH";
			case MEDIUM -> "M";
			case MEDIUM_LOW -> "ML";
			case LOW -> "L";
			case INFORMATIONAL -> "I";
		};
	}

	public int getSeverityValue() { return severityValue; }
	public long getCount() { return count; }
	public String getCompactText() { return compactText; }
	public String getAccessibleText() { return accessibleText; }
}
