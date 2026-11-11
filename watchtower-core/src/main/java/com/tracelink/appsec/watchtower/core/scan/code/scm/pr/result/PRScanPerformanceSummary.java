package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result;

import java.util.Locale;

/** Database-aggregated PR performance values for a dashboard period. */
public record PRScanPerformanceSummary(long sampleCount, double totalMs, double queueMs,
		double sourceMs, double scannersMs, double processingMs, double scmMs,
		double persistenceMs, double cleanupMs) {
	public static PRScanPerformanceSummary empty() {
		return new PRScanPerformanceSummary(0, 0, 0, 0, 0, 0, 0, 0, 0);
	}
	public String getTotalDisplay() { return format(totalMs); }
	public String getQueueDisplay() { return format(queueMs); }
	public String getSourceDisplay() { return format(sourceMs); }
	public String getScannersDisplay() { return format(scannersMs); }
	public String getProcessingDisplay() { return format(processingMs); }
	public String getScmDisplay() { return format(scmMs); }
	public String getPersistenceDisplay() { return format(persistenceMs); }
	public String getCleanupDisplay() { return format(cleanupMs); }
	private String format(double millis) {
		if (millis < 1000) return String.format(Locale.ROOT, "%.0f ms", millis);
		if (millis < 60_000) return String.format(Locale.ROOT, "%.1f s", millis / 1000.0);
		return String.format(Locale.ROOT, "%.1f min", millis / 60_000.0);
	}
}
