package com.tracelink.appsec.watchtower.core.scan.code.scm.repo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummaryCodec;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary.ScannerExecution;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.SeverityCounts;

class RunOverviewTest {

	private static RepoScanEntity scan(ScanStatus status, String scanner, String scannerStatus, RulePriority... findings) {
		RepoScanEntity scan = new RepoScanEntity();
		scan.setStatus(status);
		scan.setSeverityCounts(SeverityCounts.of(List.of(findings)));
		scan.setScannerExecutionsJson(ScanExecutionSummaryCodec.encode(List.of(
				new ScannerExecution(scanner, scannerStatus, 1_000, null))));
		return scan;
	}

	@Test
	void addsFindingsAcrossRepositoriesAndJoinsTheirScanners() {
		RunOverview overview = RunOverview.of(Map.of(ScanStatus.DONE, 2L), List.of(
				scan(ScanStatus.DONE, "BetterleaksScanner", "RAN", RulePriority.HIGH),
				scan(ScanStatus.DONE, "PMDScanner", "RAN", RulePriority.MEDIUM_HIGH, RulePriority.HIGH)));

		assertTrue(overview.detailed());
		assertEquals(3, overview.findings());
		assertEquals(List.of("2H", "1MH"), overview.severities().stream().map(s -> s.getCompactText()).toList());
		assertEquals(List.of("Betterleaks", "PMD"), overview.scanners().shown().stream().map(b -> b.name()).toList());
	}

	@Test
	void theWorstRepositoryDecidesTheRunsStatus() {
		RunOverview overview = RunOverview.of(Map.of(ScanStatus.DONE, 1L, ScanStatus.FAILED, 1L), List.of(
				scan(ScanStatus.DONE, "PMDScanner", "RAN"),
				scan(ScanStatus.FAILED, "PMDScanner", "FAILED")));

		assertEquals("Failed", overview.status().getLabel());
		assertEquals(List.of("notrun"), overview.scanners().shown().stream().map(b -> b.state()).toList(),
				"a scanner that failed anywhere in the run shows as not run");
	}

	@Test
	void aRunTooLargeToLoadIsSummarizedFromItsCounts() {
		RunOverview overview = RunOverview.of(Map.of(ScanStatus.DONE, 300L, ScanStatus.FAILED, 2L), null);

		assertFalse(overview.detailed());
		assertEquals("Failed", overview.status().getLabel());
		assertFalse(overview.scanners().isRecorded());
	}
}
