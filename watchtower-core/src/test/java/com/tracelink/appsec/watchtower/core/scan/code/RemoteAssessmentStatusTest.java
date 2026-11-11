package com.tracelink.appsec.watchtower.core.scan.code;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService.Status;

class RemoteAssessmentStatusTest {
    private static final Instant START = Instant.parse("2026-10-29T09:00:00Z");

    private static Status status(String state, boolean complete, String jobId, Map<String, String> facts, Map<String, Integer> severities) {
        return new Status("run", state, null, "c24f7f66c116156f0ee8692a2f96f71ce26d86b8", "84d065f0fad835e3394eb1c500143ec22b6a2866",
            "cr-f692003f-b177-4b0e-b843-c073bbfa940f", jobId, 0, 0, true, complete, 30, 1, severities, facts, List.of());
    }
    private static Map<String, String> times(Instant start, Instant end) {
        var facts = new LinkedHashMap<String, String>();
        if (start != null) facts.put("Started", start.toString());
        if (end != null) facts.put("Finished", end.toString());
        return facts;
    }

    @Test void severityChipsListTheWorstFirstAndSkipZeroCounts() {
        var counts = new LinkedHashMap<String, Integer>();
        counts.put("LOW", 2); counts.put("MEDIUM", 5); counts.put("CRITICAL", 3); counts.put("HIGH", 0); counts.put("ZETA", 1);
        var chips = status("COMPLETE", true, "job", Map.of(), counts).severityCounts();
        assertEquals(List.of("CRITICAL", "MEDIUM", "LOW", "ZETA"), chips.stream().map(Status.SeverityCount::name).toList());
        assertEquals("Critical", chips.get(0).label());
        assertEquals(3, chips.get(0).count());
    }

    @Test void aFinishedRunShowsItsFinalTimeFromStartToFinish() {
        var done = status("COMPLETE", true, "job", times(START, START.plusSeconds(588)), Map.of());
        assertTrue(done.finished());
        assertTrue(done.elapsedIsFinal());
        assertEquals("9m 48s", done.elapsedLabel(START.plusSeconds(9999).toEpochMilli()));
    }

    @Test void aRunWithAnEndedJobIsFinalEvenWhileItsFindingsAreStillImporting() {
        var importing = status("IMPORTING", false, "job", times(START, START.plusSeconds(120)), Map.of());
        assertFalse(importing.finished());
        assertTrue(importing.elapsedIsFinal());
        assertEquals("2m 0s", importing.elapsedLabel(START.plusSeconds(500).toEpochMilli()));
    }

    @Test void aRunningRunCountsUpToNow() {
        var running = status("RUNNING", false, "job", times(START, null), Map.of());
        assertFalse(running.finished());
        assertFalse(running.elapsedIsFinal());
        assertEquals("4m 0s", running.elapsedLabel(START.plusSeconds(240).toEpochMilli()));
    }

    @Test void aRunThatNeverStartedAJobHasNoTime() {
        var never = status("FAILED", false, null, times(START, START.plusSeconds(5)), Map.of());
        assertTrue(never.finished());
        assertNull(never.elapsedLabel(START.plusSeconds(60).toEpochMilli()));
    }

    @Test void receiptsSavedBeforeTimesWereRecordedHaveNoTimeAndNoError() {
        assertNull(status("COMPLETE", true, "job", Map.of(), Map.of()).elapsedLabel(System.currentTimeMillis()));
        assertNull(status("RUNNING", false, "job", Map.of("Started", "not a time"), Map.of()).startedAt());
    }

    @Test void sourceAndPatchAreDescribedInWords() {
        var facts = Map.of("Source files", "25", "Patch bytes", "1792");
        var status = status("COMPLETE", true, "job", facts, Map.of());
        assertEquals("25 files", status.sourceLabel());
        assertEquals("patch 1.8 KB", status.patchLabel());
        assertEquals("1 file", status("COMPLETE", true, "job", Map.of("Source files", "1"), Map.of()).sourceLabel());
        assertEquals("full source", status("COMPLETE", true, "job", Map.of("Source files", "3", "Patch bytes", "0"), Map.of()).patchLabel());
        assertEquals("patch 512 B", status("COMPLETE", true, "job", Map.of("Patch bytes", "512"), Map.of()).patchLabel());
        assertNull(status("FAILED", false, null, Map.of("Source files", "0"), Map.of()).sourceLabel());
    }

    @Test void idsAreShortenedForChipsButNeverLoseTheirStart() {
        var status = status("COMPLETE", true, "cj-c039bc14-e140-420b-a7d7-1ce32926f386", Map.of(), Map.of());
        assertEquals("cr-f692003f", status.shortReviewId());
        assertEquals("cj-c039bc14", status.shortJobId());
        assertEquals("c24f7f6", status.shortCommit());
        assertEquals("84d065f", status.shortBaseCommit());
        assertNull(status("FAILED", false, null, Map.of(), Map.of()).shortJobId());
    }

    @Test void aBlankSeverityNameFromTheProviderIsIgnoredInsteadOfBreakingTheReport() {
        var counts = new LinkedHashMap<String, Integer>();
        counts.put("", 2); counts.put("  ", 1); counts.put("HIGH", 3);
        var chips = status("COMPLETE", true, "job", Map.of(), counts).severityCounts();
        assertEquals(List.of("HIGH"), chips.stream().map(Status.SeverityCount::name).toList());
    }
}
