package com.tracelink.appsec.watchtower.core.scan.presentation;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService.Status;
import com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResult;

class ProviderTimingTest {
    private static final long LOCAL_END = Instant.parse("2026-10-29T09:00:05Z").toEpochMilli();
    private static final long START = Instant.parse("2026-10-29T09:00:00Z").toEpochMilli();

    private static ProviderAssessmentReference provider(String state, boolean complete, String started, String finished) {
        var facts = new LinkedHashMap<String, String>();
        if (started != null) facts.put("Started", started);
        if (finished != null) facts.put("Finished", finished);
        var status = new Status("run", state, null, "c1", "c0", "cr-1", "cj-1", 0, 0, true, complete, 30, 1, Map.of(), facts, List.of());
        return new ProviderAssessmentReference("AWS_SECURITY_AGENT", "run", null, status, null, null, null, null, Map.of(), 0);
    }
    private static ProviderAssessmentReference finished() { return provider("COMPLETE", true, "2026-10-29T09:00:06Z", "2026-10-29T09:09:48Z"); }
    private static ProviderAssessmentReference running() { return provider("RUNNING", false, "2026-10-29T09:00:06Z", null); }

    @Test void aFinishedReviewAddsTheTimeBetweenTheLocalEndAndItsOwnEnd() {
        var timing = ProviderTiming.of(LOCAL_END, List.of(finished()));
        assertFalse(timing.pending());
        assertEquals(Instant.parse("2026-10-29T09:09:48Z").toEpochMilli() - LOCAL_END, timing.extraMs());
        assertEquals("9m 48s", timing.duration(START, LOCAL_END));
    }

    @Test void aReviewStillRunningMeansTheScanHasNoFinalTimeYet() {
        var timing = ProviderTiming.of(LOCAL_END, List.of(running()));
        assertTrue(timing.pending());
        assertEquals(0, timing.extraMs());
        assertEquals("Running", timing.duration(START, LOCAL_END));
    }

    @Test void scansWithoutAProviderOrWithoutRecordedTimesKeepTheirLocalTime() {
        assertEquals("5.00 s", ProviderTiming.of(LOCAL_END, List.of()).duration(START, LOCAL_END));
        assertEquals("5.00 s", ProviderTiming.of(LOCAL_END, List.of(provider("COMPLETE", true, null, null))).duration(START, LOCAL_END));
        assertEquals("5.00 s", ProviderTiming.ofJson(LOCAL_END, "not json").duration(START, LOCAL_END));
    }

    @Test void aReviewThatEndedBeforeTheLocalScanAddsNothing() {
        var early = provider("COMPLETE", true, "2026-10-29T08:59:00Z", "2026-10-29T08:59:30Z");
        assertEquals(0, ProviderTiming.of(LOCAL_END, List.of(early)).extraMs());
    }

    @Test void theLatestFinishWinsRatherThanTheSum() {
        var later = provider("COMPLETE", true, "2026-10-29T09:00:06Z", "2026-10-29T09:20:00Z");
        var timing = ProviderTiming.of(LOCAL_END, List.of(finished(), later));
        assertEquals(Instant.parse("2026-10-29T09:20:00Z").toEpochMilli() - LOCAL_END, timing.extraMs());
    }

    @Test void theReportTotalAnalysisAndBarCountTheAwsWait() {
        var result = new PRScanResult();
        result.setDate(java.time.LocalDateTime.ofInstant(Instant.ofEpochMilli(LOCAL_END), java.time.ZoneId.systemDefault()));
        result.setPerformanceComplete(true);
        result.setTotalDurationMs(5000);
        result.setSourcePreparationDurationMs(1000);
        result.setScannerExecutionDurationMs(2000);
        result.setProviderAssessments(List.of(finished()));
        assertEquals("9m 48s", result.getTotalDurationDisplay(), "5 s of local scanning plus 9 min 43 s of AWS");
        assertEquals("9m 45s", result.getScannerExecutionDurationDisplay());
        assertEquals("99.8%", result.getStageWidth("analysis"));
        result.setProviderAssessments(List.of(running()));
        assertEquals("Running", result.getTotalDurationDisplay());
        assertEquals("Running", result.getScannerExecutionDurationDisplay());
    }

    @Test void aPullRequestRowShowsTheWholeDurationAndTheRealFinishTime() {
        var row = mock(PRScanRepository.ResultRow.class);
        when(row.getStartDate()).thenReturn(START);
        when(row.getEndDate()).thenReturn(LOCAL_END);
        when(row.getProviderSummaryJson()).thenReturn(ProviderAssessmentReference.encode(List.of(finished())));
        var item = HomeActivityItem.fromPullRequestRow(row, Map.of(), 0);
        assertEquals("9m 48s", item.getDuration());
        assertEquals(java.time.LocalDateTime.ofInstant(Instant.parse("2026-10-29T09:09:48Z"), java.time.ZoneId.systemDefault()), item.getCompletedTime());

        when(row.getProviderSummaryJson()).thenReturn(ProviderAssessmentReference.encode(List.of(running())));
        assertEquals("Running", HomeActivityItem.fromPullRequestRow(row, Map.of(), 0).getDuration());
        when(row.getProviderSummaryJson()).thenReturn(null);
        assertEquals("5.00 s", HomeActivityItem.fromPullRequestRow(row, Map.of(), 0).getDuration());
    }
}
