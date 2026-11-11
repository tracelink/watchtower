package com.tracelink.appsec.watchtower.core.metrics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import com.tracelink.appsec.watchtower.core.metrics.MetricsProjectionRepository.DailyScanMetric;
import com.tracelink.appsec.watchtower.core.metrics.MetricsProjectionRepository.DailyViolationMetric;
import com.tracelink.appsec.watchtower.core.metrics.MetricsProjectionRepository.ScannerTimingMetric;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestSyncSettingsEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PullRequestSyncSettingsService;

import net.minidev.json.JSONObject;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MetricsCacheServiceTest {
	@Mock MetricsProjectionRepository projections;
	@Mock PullRequestSyncSettingsService settingsService;
	private MetricsCacheService service;

	@BeforeEach
	void setUp() {
		service = new MetricsCacheService(projections, settingsService);
		when(projections.oldestDate("pull_request"))
				.thenReturn(LocalDate.now().minusMonths(2).atStartOfDay());
		when(projections.findScans(eq("pull_request"), anyLong(), anyLong())).thenReturn(List.of(
				new DailyScanMetric(LocalDate.now().atStartOfDay(), 2, 3,
						2_000, 2, 4_096, 2)));
		when(projections.findViolations(eq("pull_request"), anyLong(), anyLong())).thenReturn(List.of(
				new DailyViolationMetric(LocalDate.now().atStartOfDay(), "XXE", 2),
				new DailyViolationMetric(LocalDate.now().atStartOfDay(), "SQLi", 1)));
	}

	@Test
	void allTimeReportsScansWithImpossibleDates() {
		when(projections.implausibleScanCount("pull_request")).thenReturn(1L);

		JSONObject allTime = service.getScansByPeriod(CodeScanType.PULL_REQUEST, "all-time");
		assertEquals(1L, allTime.get("impossibleDates"));
		assertEquals("2015-01-01", allTime.get("impossibleBefore"));
		// Shorter ranges never mention it: their start is fixed, so old dates cannot stretch them.
		JSONObject week = service.getScansByPeriod(CodeScanType.PULL_REQUEST, "last-week");
		assertEquals(null, week.get("impossibleDates"));
	}

	@Test
	void readsChartDataFromProjectionForRequestedPeriod() {
		JSONObject result = service.getScansByPeriod(CodeScanType.PULL_REQUEST, "last-week");
		assertEquals(7, ((List<?>) result.get("labels")).size());
		assertEquals(2L, ((List<?>) result.get("counts")).get(6));
		verify(projections).findScans(eq("pull_request"), anyLong(), anyLong());
	}

	@Test
	void supportsThirtyDayPeriod() {
		JSONObject result = service.getViolationsByPeriod(CodeScanType.PULL_REQUEST,
				"last-thirty-days");
		assertEquals(30, ((List<?>) result.get("labels")).size());
		String finalLabel = String.valueOf(((List<?>) result.get("labels")).get(29));
		org.junit.jupiter.api.Assertions.assertTrue(finalLabel.matches("\\d{2} [A-Z][a-z]{2}"));
	}

	@Test
	void prPerformanceTrendUsesWeightedPhaseAveragesPerBucket() {
		when(projections.findScans(eq("pull_request"), anyLong(), anyLong())).thenReturn(List.of(
				new DailyScanMetric(LocalDate.now().atStartOfDay(), 2, 3, 2_000, 2,
						4_096, 2, 2, 4_000, 200, 1_000, 2_000, 600, 100,
						60, 40)));
		when(projections.findPrScannerTimings(anyLong(), anyLong())).thenReturn(List.of(
				new ScannerTimingMetric(LocalDate.now().atStartOfDay(),
						"[{\"scannerName\":\"PMDScanner\",\"durationMs\":1200}]")));

		JSONObject result = service.getPrPerformanceByPeriod("last-week");

		assertEquals(7, ((List<?>) result.get("labels")).size());
		assertEquals(2_000D, ((List<?>) result.get("totalMs")).get(6));
		assertEquals(500D, ((List<?>) result.get("sourceMs")).get(6));
		assertEquals(1_000D, ((List<?>) result.get("scannersMs")).get(6));
		assertEquals(300D, ((List<?>) result.get("processingMs")).get(6));
		@SuppressWarnings("unchecked")
		List<java.util.Map<String, Object>> scannerSeries =
				(List<java.util.Map<String, Object>>) result.get("scannerSeries");
		assertEquals("PMDScanner", scannerSeries.get(0).get("name"));
		assertEquals(1_200D, ((List<?>) scannerSeries.get(0).get("values")).get(6));
	}

	@Test
	void repositorySpeedUsesWeightedElapsedTimeForPresetAndCustomRanges() {
		LocalDate today = LocalDate.now();
		when(projections.oldestDate("repository")).thenReturn(today.minusDays(10).atStartOfDay());
		when(projections.findScans(eq("repository"), anyLong(), anyLong())).thenReturn(List.of(
				new DailyScanMetric(today.atStartOfDay(), 2, 0, 6_000, 2, 0, 0),
				new DailyScanMetric(today.atStartOfDay(), 1, 0, 6_000, 1, 0, 0)));

		JSONObject preset = service.getScanDurationByPeriod(CodeScanType.REPOSITORY, "last-week");
		assertEquals(3L, ((List<?>) preset.get("samples")).get(6));
		assertEquals(4_000D, ((List<?>) preset.get("totalMs")).get(6));
		JSONObject custom = service.getScanDurationByPeriod(CodeScanType.REPOSITORY, today, today);
		assertEquals(List.of(today.toString()), custom.get("labels"));
		assertEquals(List.of(4_000D), custom.get("totalMs"));
	}

	@Test
	void repositoryChartsIncludeFindingsImportedAfterTheLocalScanFinished() {
		LocalDate today = LocalDate.now();
		when(projections.oldestDate("repository")).thenReturn(today.minusDays(10).atStartOfDay());
		when(projections.findViolations(eq("repository"), anyLong(), anyLong())).thenReturn(List.of(
				new DailyViolationMetric(today.atStartOfDay(), "Local rule", 1),
				new DailyViolationMetric(today.atStartOfDay(), "AWS Security Agent — security review", 3)));
		when(projections.repositoryProviderFindingCount(0, Long.MAX_VALUE)).thenReturn(3L);
		when(projections.sum("repository", "violation_count")).thenReturn(1L);

		JSONObject trend = service.getViolationsByPeriod(CodeScanType.REPOSITORY, "last-week");
		assertEquals(4L, ((List<?>) trend.get("counts")).get(6));
		JSONObject rules = service.getViolationsByType(CodeScanType.REPOSITORY, "last-week");
		assertEquals(List.of("AWS Security Agent — security review", "Local rule"), rules.get("labels"));
		assertEquals(4L, service.getViolationCount(CodeScanType.REPOSITORY));
		JSONObject custom = service.getViolationsByPeriod(CodeScanType.REPOSITORY, today, today);
		assertEquals(List.of(4L), custom.get("counts"));
	}

	@Test
	void customSystemDateRangeIsInclusiveAndDaily() {
		LocalDate today = LocalDate.now();
		JSONObject result = service.getScansByPeriod(CodeScanType.PULL_REQUEST,
				today.minusDays(2), today);
		assertEquals(3, ((List<?>) result.get("labels")).size());
		assertEquals(today.toString(), ((List<?>) result.get("labels")).get(2));
	}

	@Test
	void customRangeUsesConfiguredSystemZoneInsteadOfUtc() {
		MetricsCacheService indiaService = new MetricsCacheService(projections, settingsService,
				"Asia/Kolkata");
		LocalDate start = LocalDate.of(2026, 9, 1);
		LocalDate end = LocalDate.of(2026, 9, 2);

		indiaService.getScansByPeriod(CodeScanType.PULL_REQUEST, start, end);

		ZoneId india = ZoneId.of("Asia/Kolkata");
		verify(projections).findScans("pull_request",
				start.atStartOfDay(india).toInstant().toEpochMilli(),
				end.plusDays(1).atStartOfDay(india).toInstant().toEpochMilli());
	}

	@Test
	void rejectsReversedCustomRange() {
		LocalDate today = LocalDate.now();
		assertThrows(IllegalArgumentException.class, () -> service.getScansByPeriod(
				CodeScanType.PULL_REQUEST, today, today.minusDays(1)));
	}

	@Test
	void violationChartsUseStoredNonInformationalCounts() {
		JSONObject result = service.getViolationsByType(CodeScanType.PULL_REQUEST, "last-week");
		assertEquals(List.of("SQLi", "XXE"), result.get("labels"));
		assertEquals(List.of(1L, 2L), result.get("counts"));
	}

	@Test
	void rejectsUnknownPeriod() {
		assertThrows(IllegalArgumentException.class,
				() -> service.getScansByPeriod(CodeScanType.PULL_REQUEST, "foobar"));
	}

	@Test
	void scalarMetricsAreQueriedOnDemand() {
		when(projections.sum("pull_request", "scan_count")).thenReturn(42L);
		when(projections.average("pull_request", "duration_sum_ms", "duration_count"))
				.thenReturn(2_000D);
		assertEquals(42, service.getScanCount(CodeScanType.PULL_REQUEST));
		assertEquals("2.00 s", service.getAverageScanTimeString(CodeScanType.PULL_REQUEST));
	}

	@Test
	void performanceWindowComesFromSettings() {
		PullRequestSyncSettingsEntity settings = new PullRequestSyncSettingsEntity();
		settings.setPerformanceWindowDays(14);
		when(settingsService.getSettings()).thenReturn(settings);
		assertEquals(14, service.getPrPerformanceWindowDays());
	}

	@Test
	void homeMetricsAggregateAllModulesWithoutAveragingModuleAverages() {
		when(projections.findScans(eq("pull_request"), anyLong(), anyLong())).thenReturn(List.of(
				new DailyScanMetric(LocalDate.now().atStartOfDay(), 2, 3, 2_000, 2, 0, 0)));
		when(projections.findScans(eq("upload"), anyLong(), anyLong())).thenReturn(List.of(
				new DailyScanMetric(LocalDate.now().atStartOfDay(), 1, 4, 4_000, 1, 0, 0)));
		when(projections.findScans(eq("container"), anyLong(), anyLong())).thenReturn(List.of(
				new DailyScanMetric(LocalDate.now().atStartOfDay(), 3, 5, 9_000, 3, 0, 0)));
		when(projections.findScans(eq("repository"), anyLong(), anyLong())).thenReturn(List.of(
				new DailyScanMetric(LocalDate.now().atStartOfDay(), 2, 6, 8_000, 2, 0, 0)));

		HomeMetricsSnapshot snapshot = service.getHomeMetrics(1L, 2L);

		assertEquals(8, snapshot.completed());
		assertEquals(18, snapshot.findings());
		assertEquals(2_875D, snapshot.averageDurationMillis());
	}
}
