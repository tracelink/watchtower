package com.tracelink.appsec.watchtower.core.scan.code.scm.repo;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.presentation.ScanFindingSummary;
import com.tracelink.appsec.watchtower.core.scan.presentation.ScannerBadge;
import com.tracelink.appsec.watchtower.core.scan.presentation.SeverityCountPresentationModel;
import com.tracelink.appsec.watchtower.core.scan.presentation.StatusPresentationModel;

/**
 * One run on the Runs list (UAT #32): the status of its worst repository, its findings and the
 * scanners that took part. A run too large to load row by row is summarized from its status counts
 * only ({@code detailed} false), so the list stays light on large plans.
 */
public record RunOverview(StatusPresentationModel status, long findings,
		List<SeverityCountPresentationModel> severities, ScannerBadge.Summary scanners, boolean detailed) {

	/** Worst first: failed, running, partial, queued/finished/unknown, full. */
	private static final List<String> TONE_ORDER = List.of("danger", "info", "warning", "neutral", "success");

	public static RunOverview of(Map<ScanStatus, Long> statuses, List<RepoScanEntity> scans) {
		if (scans == null) {
			return new RunOverview(fromCounts(statuses), 0, List.of(), ScannerBadge.Summary.EMPTY, false);
		}
		StatusPresentationModel worst = scans.stream().map(StatusPresentationModel::from)
				.min(Comparator.comparingInt(RunOverview::rank)).orElse(fromCounts(statuses));
		Map<RulePriority, Long> counts = new java.util.EnumMap<>(RulePriority.class);
		long unclassified = 0;
		long findings = 0;
		List<ScannerBadge.Summary> tiles = new ArrayList<>();
		for (RepoScanEntity scan : scans) {
			ScanFindingSummary summary = ScanFindingSummary.of(scan.getSeverityCounts(),
					scan.getFindingCount(), scan.getProviderAssessments());
			for (var severity : summary.severities()) {
				if (severity.getSeverityValue() == 0) unclassified += severity.getCount();
				else counts.merge(RulePriority.valueOf(severity.getSeverityValue()),
						severity.getCount(), Long::sum);
			}
			findings += summary.total();
			tiles.add(ScannerBadge.from(scan.getScannerExecutionsJson(), scan.getProviderSummaryJson()));
		}
		return new RunOverview(worst, findings,
				SeverityCountPresentationModel.fromTotals(counts, unclassified), join(tiles), true);
	}

	private static int rank(StatusPresentationModel status) {
		int index = TONE_ORDER.indexOf(status.getTone());
		return index < 0 ? TONE_ORDER.size() : index;
	}

	private static StatusPresentationModel fromCounts(Map<ScanStatus, Long> statuses) {
		Map<ScanStatus, Long> safe = statuses == null ? Map.of() : statuses;
		for (ScanStatus status : List.of(ScanStatus.FAILED, ScanStatus.IN_PROGRESS, ScanStatus.NOT_STARTED, ScanStatus.DONE)) {
			if (safe.getOrDefault(status, 0L) > 0) {
				return StatusPresentationModel.from(status);
			}
		}
		return StatusPresentationModel.from((ScanStatus) null);
	}

	/** One tile per scanner across the run; a scanner that did not run anywhere wins over "ran". */
	private static ScannerBadge.Summary join(List<ScannerBadge.Summary> summaries) {
		Map<String, ScannerBadge> shown = new LinkedHashMap<>();
		Map<String, ScannerBadge> unused = new LinkedHashMap<>();
		for (ScannerBadge.Summary summary : summaries) {
			for (ScannerBadge badge : summary.shown()) {
				ScannerBadge seen = shown.get(badge.name());
				if (seen == null || (ScannerBadge.RAN.equals(seen.state()) && !ScannerBadge.RAN.equals(badge.state()))) {
					shown.put(badge.name(), badge);
				}
			}
			summary.unused().forEach(badge -> unused.putIfAbsent(badge.name(), badge));
		}
		shown.keySet().forEach(unused::remove);
		return new ScannerBadge.Summary(List.copyOf(shown.values()), List.copyOf(unused.values()));
	}
}
