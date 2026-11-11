package com.tracelink.appsec.watchtower.core.metrics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService;
import com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference;

class MetricsProjectionRepositoryTest {
    @Test void readsLateProviderResultsFromSavedRepositorySummariesOncePerRun() {
        var records = mock(LedgerRepository.class);
        var status = new RemoteAssessmentService.Status("run-1", "COMPLETE", null, null, null,
            "review", "job", 3, 0, true, true, null, 1,
            Map.of("HIGH", 2, "INFORMATIONAL", 1));
        var reference = new ProviderAssessmentReference("AWS_SECURITY_AGENT", "run-1", "artifact",
            status, null, null, "AWS Security Agent — security review", null, Map.of(), 0);
        var summary = ProviderAssessmentReference.encode(List.of(reference, reference));
        var row = Map.<String, Object>of("id", 7L,
            "ended", Instant.parse("2026-10-20T12:00:00Z").toEpochMilli(), "summary", summary);
        when(records.maps(anyString(), eq(0), eq(200), eq(0L), eq(ScanStatus.DONE),
            eq(0L), eq(Long.MAX_VALUE))).thenReturn(List.of(row));

        var repository = new MetricsProjectionRepository(records, "UTC");
        var findings = repository.repositoryProviderViolations(0, Long.MAX_VALUE);

        assertEquals(1, findings.size());
        assertEquals(LocalDate.of(2026, 10, 20), findings.getFirst().date().toLocalDate());
        assertEquals("AWS Security Agent — security review", findings.getFirst().name());
        assertEquals(2, findings.getFirst().count());
    }

    @Test void allTimeStartsAtTheFirstPlausibleDayAndCountsImpossibleDates() {
        var records = mock(LedgerRepository.class);
        long bound = MetricsProjectionRepository.EARLIEST_PLAUSIBLE_SCAN_MILLIS;
        when(records.scalar(eq(Long.class), org.mockito.ArgumentMatchers.contains("MIN(m.bucketStart)"),
            eq("pull_request"), eq(bound))).thenReturn(Instant.parse("2026-01-05T00:00:00Z").toEpochMilli());
        when(records.scalar(eq(Long.class), org.mockito.ArgumentMatchers.contains("m.bucketStart<?2"),
            eq("pull_request"), eq(bound))).thenReturn(1L);

        var repository = new MetricsProjectionRepository(records, "UTC");

        assertEquals(LocalDate.of(2026, 1, 5), repository.oldestDate("pull_request").toLocalDate());
        assertEquals(1L, repository.implausibleScanCount("pull_request"));
        assertEquals(Instant.parse("2015-01-01T00:00:00Z").toEpochMilli(), bound);
    }
}
