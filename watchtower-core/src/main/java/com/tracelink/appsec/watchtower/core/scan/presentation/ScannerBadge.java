package com.tracelink.appsec.watchtower.core.scan.presentation;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary.ScannerExecution;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummaryCodec;
import com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference;

/**
 * One scanner of one scan as a small icon tile: {@code state} is ran, running or notrun (the CSS modifier)
 * and {@code label} is the hover/accessible text, e.g. "PMD · ran · 9.4 s".
 */
public record ScannerBadge(String name, String icon, String state, String label) {

	public static final String RAN = "ran";
	public static final String NOT_RUN = "notrun";
	/** A scanner that is still working: yellow, because red would read as an error. */
	public static final String RUNNING = "running";
	/** A scanner with no file of its types in the scan: finished, nothing to check (a dashed tile). */
	public static final String NOT_NEEDED = "na";
	/** Tiles a list row draws before folding the rest into "+N". */
	static final int LIST_TILES = 2;

	/**
	 * A scan's tiles. Every registered scanner is recorded, so scanners that were not part of the
	 * scan (no rules in its ruleset, or turned off) are summarized in {@code unused} rather than
	 * drawn: a red tile then always means a scanner that should have run and did not finish.
	 */
	public record Summary(List<ScannerBadge> shown, List<ScannerBadge> unused) {
		public static final Summary EMPTY = new Summary(List.of(), List.of());

		public Summary {
			shown = List.copyOf(shown);
			unused = List.copyOf(unused);
		}

		public boolean isRecorded() {
			return !shown.isEmpty() || !unused.isEmpty();
		}

		/** Hover text for the "+N" chip, e.g. "Not used in this scan: JSON (no rules), Opengrep (off)". */
		public String getUnusedLabel() {
			return "Not used in this scan: " + unused.stream().map(ScannerBadge::label)
					.collect(Collectors.joining(", "));
		}

		/**
		 * The tiles a list row draws so the cell never wraps: every tile when there are few, otherwise
		 * the scanners that did not finish first, then the rest, up to {@link #LIST_TILES}.
		 */
		public List<ScannerBadge> getVisible() {
			if (shown.size() <= LIST_TILES + 1) {
				return shown;
			}
			return java.util.stream.Stream.concat(
					shown.stream().filter(tile -> NOT_RUN.equals(tile.state())),
					shown.stream().filter(tile -> !NOT_RUN.equals(tile.state())))
					.limit(LIST_TILES).toList();
		}

		/** How many scanners a list row folds into its "+N" chip: hidden tiles plus unused scanners. */
		public int getMoreCount() {
			return shown.size() - getVisible().size() + unused.size();
		}

		/** Hover text for a list row's "+N" chip, e.g. "Also: PMD · ran · 2.1 s · Not used in this scan: JSON (no rules)". */
		public String getMoreLabel() {
			List<ScannerBadge> visible = getVisible();
			String hidden = shown.stream().filter(tile -> !visible.contains(tile)).map(ScannerBadge::label)
					.collect(Collectors.joining(", "));
			if (hidden.isEmpty()) {
				return getUnusedLabel();
			}
			return unused.isEmpty() ? "Also: " + hidden : "Also: " + hidden + " · " + getUnusedLabel();
		}
	}

	/** Tiles from a scan's recorded executions (JSON) and remote provider assessments. */
	public static Summary from(String executionsJson, String providerJson) {
		return from(ScanExecutionSummaryCodec.decode(executionsJson), providerJson);
	}

	public static Summary from(List<ScannerExecution> executions, String providerJson) {
		return fromReferences(executions, providers(providerJson));
	}

	/** Tiles from executions and already-decoded provider assessments (report pages). */
	public static Summary fromReferences(List<ScannerExecution> executions,
			List<ProviderAssessmentReference> providerAssessments) {
		List<ScannerBadge> shown = new ArrayList<>();
		List<ScannerBadge> unused = new ArrayList<>();
		// Remote providers first: they are the slow, separately-billed reviews people look for.
		for (ProviderAssessmentReference provider : providerAssessments == null
				? List.<ProviderAssessmentReference>of() : providerAssessments) {
			shown.add(of(provider));
		}
		for (ScannerExecution execution : executions) {
			ScannerIdentity identity = ScannerIdentity.of(execution.scannerName());
			String status = execution.status() == null ? "" : execution.status();
			switch (status) {
				case "SKIPPED" -> unused.add(new ScannerBadge(identity.name(), identity.icon(), NOT_RUN,
						identity.name() + " (no rules)"));
				case "DISABLED" -> unused.add(new ScannerBadge(identity.name(), identity.icon(), NOT_RUN,
						identity.name() + " (off)"));
				case "NOT_APPLICABLE" -> shown.add(new ScannerBadge(identity.name(), identity.icon(), NOT_NEEDED,
						identity.name() + " · not needed" + reason(execution.reason())));
				default -> shown.add(of(identity, status, execution));
			}
		}
		return new Summary(shown, unused);
	}

	private static ScannerBadge of(ScannerIdentity identity, String status, ScannerExecution execution) {
		String detail = switch (status) {
			case "RAN" -> "ran · " + duration(execution.durationMs());
			case "REUSED" -> "reused an earlier result";
			case "FAILED" -> "failed";
			default -> "did not run";
		};
		boolean ran = "RAN".equals(status) || "REUSED".equals(status);
		return new ScannerBadge(identity.name(), identity.icon(), ran ? RAN : NOT_RUN,
				identity.name() + " · " + detail + reason(execution.reason()));
	}

	static ScannerBadge of(ProviderAssessmentReference provider) {
		ScannerIdentity identity = ScannerIdentity.of(provider.provider());
		boolean complete = provider.status() != null && provider.status().complete();
		if (!complete && provider.status() != null && provider.status().inProgress()) {
			return new ScannerBadge(identity.name(), identity.icon(), RUNNING, identity.name() + " · running");
		}
		String reason = provider.status() == null ? null : provider.status().reasonLabel();
		return new ScannerBadge(identity.name(), identity.icon(), complete ? RAN : NOT_RUN,
				identity.name() + (complete ? " · ran" : " · did not finish") + reason(reason));
	}

	private static List<ProviderAssessmentReference> providers(String json) {
		try {
			return ProviderAssessmentReference.decode(json);
		} catch (IllegalArgumentException unreadable) {
			// The status column already reports unreadable metadata; tiles simply omit providers.
			return List.of();
		}
	}

	private static String reason(String reason) {
		return reason == null || reason.isBlank() ? "" : " · " + reason;
	}

	private static String duration(long millis) {
		if (millis <= 0) return "time not recorded";
		if (millis < 1_000) return millis + " ms";
		return String.format("%.1f s", millis / 1_000d);
	}
}
