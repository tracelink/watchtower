package com.tracelink.appsec.watchtower.core.scan.code.scm.pr;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary.ScannerExecution;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummaryCodec;

/** Immutable performance snapshot for one completed PR scan. */
public record PRScanTimings(long queueWaitMs, long totalMs, long sourcePreparationMs,
		long scannerExecutionMs, long resultProcessingMs, long scmReportingMs,
		long persistenceMs, long cleanupMs, int changedFileCount, String scanScope,
		String sourceStrategy, List<ScannerTiming> scanners, boolean complete) {

	public PRScanTimings {
		queueWaitMs = nonNegative(queueWaitMs);
		totalMs = nonNegative(totalMs);
		sourcePreparationMs = nonNegative(sourcePreparationMs);
		scannerExecutionMs = nonNegative(scannerExecutionMs);
		resultProcessingMs = nonNegative(resultProcessingMs);
		scmReportingMs = nonNegative(scmReportingMs);
		persistenceMs = nonNegative(persistenceMs);
		cleanupMs = nonNegative(cleanupMs);
		changedFileCount = Math.max(0, changedFileCount);
		scanScope = scanScope == null ? "UNKNOWN" : scanScope;
		sourceStrategy = sourceStrategy == null ? "UNKNOWN" : sourceStrategy;
		scanners = scanners == null ? List.of() : List.copyOf(scanners);
	}

	private static final Logger LOG = LoggerFactory.getLogger(PRScanTimings.class);
	private static final ObjectMapper JSON = new ObjectMapper();

	/** Stored per-scanner run times; unreadable or absent JSON yields an empty list. */
	public static List<ScannerTiming> readScanners(String timingsJson) {
		if (timingsJson == null || timingsJson.isBlank()) return List.of();
		try {
			return List.copyOf(JSON.readValue(timingsJson, new TypeReference<List<ScannerTiming>>() { }));
		} catch (JsonProcessingException | IllegalArgumentException e) {
			LOG.warn("Could not parse stored scanner timings", e);
			return List.of();
		}
	}

	/**
	 * Every scanner of a PR scan. Scanners that ran are stored as timings; failed, skipped and reused
	 * ones as executions. An explicit execution state overrides a timing: duration alone is not success.
	 */
	public static List<ScannerExecution> executions(String timingsJson, String executionsJson) {
		// A timing is stored under the scanner's class name and an execution under its short name, so
		// merge on the name people see; otherwise one scanner shows twice, once ran and once failed.
		Map<String, ScannerExecution> byScanner = new LinkedHashMap<>();
		readScanners(timingsJson).forEach(timing -> byScanner.put(identityOf(timing.scannerName()),
				new ScannerExecution(timing.scannerName(), "RAN", timing.durationMs(), null)));
		ScanExecutionSummaryCodec.decode(executionsJson).forEach(execution -> {
			ScannerExecution timed = byScanner.get(identityOf(execution.scannerName()));
			byScanner.put(identityOf(execution.scannerName()), timed != null && execution.durationMs() == 0
					? new ScannerExecution(execution.scannerName(), execution.status(), timed.durationMs(),
							execution.reason())
					: execution);
		});
		return new ArrayList<>(byScanner.values());
	}

	private static String identityOf(String scannerName) {
		return com.tracelink.appsec.watchtower.core.scan.presentation.ScannerIdentity.of(scannerName).name();
	}

	private static long nonNegative(long value) {
		return Math.max(0, value);
	}

	public record ScannerTiming(String scannerName, long durationMs) {
		public ScannerTiming {
			if (scannerName == null || scannerName.isBlank()) {
				throw new IllegalArgumentException("Scanner name is required");
			}
			durationMs = nonNegative(durationMs);
		}
	}
}
