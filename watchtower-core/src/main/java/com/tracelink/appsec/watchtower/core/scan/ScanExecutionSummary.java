package com.tracelink.appsec.watchtower.core.scan;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanExecutionSnapshot;
import java.util.Collections;
import java.util.List;

/** Immutable execution evidence. The legacy rulesEvaluated field counts selected rules only. */
public record ScanExecutionSummary(Integer rulesEvaluated, List<ScannerExecution> scanners,
		CodeScanExecutionSnapshot codeSnapshot) {
	/**
	 * A scanner that was on and had rules, but the scan held no file of the types it analyses.
	 * Unlike SKIPPED it is a finished check: the scan is complete without it.
	 */
	public static final String NOT_APPLICABLE = "NOT_APPLICABLE";

	public ScanExecutionSummary(Integer rulesEvaluated, List<ScannerExecution> scanners) {
		this(rulesEvaluated, scanners, null);
	}

	public ScanExecutionSummary {
		scanners = scanners == null ? Collections.emptyList() : List.copyOf(scanners);
	}

	public long getRanCount() {
		return scanners.stream().filter(ScannerExecution::isRan).count();
	}

	public long getSkippedCount() {
		return scanners.stream().filter(scanner -> "SKIPPED".equals(scanner.status())).count();
	}

	public long getNotApplicableCount() {
		return scanners.stream().filter(scanner -> NOT_APPLICABLE.equals(scanner.status())).count();
	}

	public long getDisabledCount() { return scanners.stream().filter(scanner -> "DISABLED".equals(scanner.status())).count(); }
 public long getUnsupportedCount() { return scanners.stream().filter(scanner -> "UNSUPPORTED".equals(scanner.status())).count(); }

 public long getFailedCount() {
		return scanners.stream().filter(scanner -> "FAILED".equals(scanner.status())).count();
	}

	public long getReusedCount() {
		return scanners.stream().filter(scanner -> "REUSED".equals(scanner.status())).count();
	}

	public boolean isRecorded() {
		return rulesEvaluated != null;
	}

	public record ScannerExecution(String scannerName, String status, long durationMs,
			String reason) {
		@JsonIgnore
		public boolean isRan() {
			return "RAN".equals(status);
		}

		/** The scanner's display name, the same everywhere (e.g. "ESLint", not "EsLintScanner"). */
		@JsonIgnore
		public String getDisplayName() {
			return com.tracelink.appsec.watchtower.core.scan.presentation.ScannerIdentity.of(scannerName).name();
		}

		/** The scanner's icon, as on Home's Scanners column. */
		@JsonIgnore
		public String getIcon() {
			return com.tracelink.appsec.watchtower.core.scan.presentation.ScannerIdentity.of(scannerName).icon();
		}

		/** Status for people, e.g. "Skipped" rather than "SKIPPED" (UAT #13). */
		@JsonIgnore
		public String getLabel() {
			if (NOT_APPLICABLE.equals(status)) {
				return "Not needed";
			}
			String text = status == null ? "Unknown" : status.replace('_', ' ').toLowerCase(java.util.Locale.ROOT);
			return Character.toUpperCase(text.charAt(0)) + text.substring(1);
		}

		/** The same chip tones as other statuses: failed is danger, skipped is a warning. */
		@JsonIgnore
		public String getTone() {
			return switch (status == null ? "" : status) {
				case "RAN" -> "success";
				case "FAILED" -> "danger";
				case "SKIPPED" -> "warning";
				case "REUSED" -> "info";
				default -> "neutral";
			};
		}
	}
}
