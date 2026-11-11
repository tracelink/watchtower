package com.tracelink.appsec.watchtower.core.scan.presentation;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import com.tracelink.appsec.watchtower.core.job.AsyncJobStatus;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.*;
import com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.*;

class ScanAssessmentTest {
    private static final RuleExecutionIdentity RULE = new RuleExecutionIdentity(1L, "regex", "a".repeat(64), null, null);
    private static CodeScanExecutionSnapshot snapshot(String status) {
        return new CodeScanExecutionSnapshot(1, 1L, "Fixture", RulePriority.HIGH,
                List.of(new CodeScanExecutionSnapshot.SelectedRule(RULE, "Rule", RulePriority.HIGH,
                        RuleState.ACTIVE, "regex", "UNKNOWN", null)),
                List.of(new CodeScanExecutionSnapshot.EngineExecution("regex",
                        new EngineExecutionIdentity("regex", "1", "b".repeat(64), true), status)), null);
    }

    @Test void successfulProcessingIsSeparateFromKnownCoverage() {
        var historical = ScanAssessment.of(ScanStatus.DONE, null, List.of());
        assertEquals("COMPLETED", historical.processing());
        assertEquals("UNKNOWN", historical.completeness());
        assertFalse(historical.complete());
        assertTrue(ScanAssessment.of(ScanStatus.DONE, snapshot("RAN"), List.of()).complete());
        for (String state : List.of("FAILED", "SKIPPED", "DISABLED", "UNSUPPORTED")) {
            var failed = ScanAssessment.of(ScanStatus.DONE, snapshot(state), List.of());
            assertEquals("COMPLETED", failed.processing());
            assertEquals("INCOMPLETE", failed.completeness());
            assertFalse(failed.reasons().isEmpty());
        }
        assertEquals("UNKNOWN", ScanAssessment.of(ScanStatus.DONE, snapshot("UNKNOWN"), List.of()).completeness());
    }

    @Test void aScannerWithNoMatchingFilesFinishedItsPartSoTheScanStaysComplete() {
        var assessment = ScanAssessment.of(ScanStatus.DONE, snapshot("NOT_APPLICABLE"), List.of());
        assertTrue(assessment.complete());
        assertTrue(assessment.reasons().isEmpty());
        assertFalse(ScanAssessment.of(ScanStatus.DONE, snapshot("SKIPPED"), List.of()).complete());
    }

    private static CodeScanExecutionSnapshot failedEngineWithRules(int rules, String engineStatus, String ruleCoverage) {
        var selected = new java.util.ArrayList<CodeScanExecutionSnapshot.SelectedRule>();
        for (int i = 0; i < rules; i++) {
            selected.add(new CodeScanExecutionSnapshot.SelectedRule(
                    new RuleExecutionIdentity((long) i + 1, "pmd", "a".repeat(64), null, null), "Rule" + i,
                    RulePriority.HIGH, RuleState.ACTIVE, "com.example.pmd.scanner.PMDScanner", ruleCoverage, null));
        }
        return new CodeScanExecutionSnapshot(1, 1L, "Fixture", RulePriority.HIGH, selected,
                List.of(new CodeScanExecutionSnapshot.EngineExecution("com.example.pmd.scanner.PMDScanner",
                        new EngineExecutionIdentity("pmd", "1", "b".repeat(64), true), engineStatus)), null);
    }

    @Test void aFailedScannerIsNamedOnceByItsOwnNameAndNotByItsClassOrEveryRule() {
        var assessment = ScanAssessment.of(ScanStatus.DONE, failedEngineWithRules(300, "FAILED", "FAILED"), List.of());

        assertEquals(List.of("PMD failed."), assessment.reasons());
        assertEquals("INCOMPLETE", assessment.completeness());
    }

    @Test void aFailedScannerSaysWhyWhenItsReasonWasRecorded() {
        var assessment = ScanAssessment.of(ScanStatus.DONE, snapshot("FAILED"), List.of(),
                Map.of("Regex", "2 problems: a/b.java (LexException); Parsing error"));
        assertEquals(List.of("Regex failed (2 problems: a/b.java (LexException); Parsing error)."),
                assessment.reasons());
    }

    @Test void aScanWithScannerExecutionsButNoRuleSnapshotIsNotCalledAnOlderScan() {
        var failed = new com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary.ScannerExecution("PMD", "FAILED", 100, "2 problems: a.java (LexException)");
        var ran = new com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary.ScannerExecution("Regex", "RAN", 10, null);

        var partial = ScanAssessment.ofExecutions(ScanStatus.DONE, List.of(ran, failed), List.of());
        assertEquals("INCOMPLETE", partial.completeness());
        assertEquals(List.of("PMD failed (2 problems: a.java (LexException))."), partial.reasons());

        var allRan = ScanAssessment.ofExecutions(ScanStatus.DONE, List.of(ran), List.of());
        assertEquals("UNKNOWN", allRan.completeness());
        assertTrue(allRan.reasons().get(0).contains("which rules ran was not recorded"));
        assertFalse(allRan.reasons().get(0).contains("older"));
    }

    @Test void aScannerWithNoRulesInTheRulesetDoesNotMakeAnUploadPartial() {
        // Dev E2E G03: a one-rule ruleset left 7 scanners "skipped (no rules)" and the scan read "Partial scan".
        var ran = new com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary.ScannerExecution("Regex", "RAN", 10, null);
        var noRules = new com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary.ScannerExecution("PMD", "SKIPPED", 0, null);
        var off = new com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary.ScannerExecution("JSON", "DISABLED", 0, null);

        var fine = ScanAssessment.ofExecutions(ScanStatus.DONE, List.of(ran, noRules), List.of());
        assertEquals("UNKNOWN", fine.completeness());
        assertFalse(fine.reasons().stream().anyMatch(r -> r.contains("PMD")));

        var turnedOff = ScanAssessment.ofExecutions(ScanStatus.DONE, List.of(ran, noRules, off), List.of());
        assertEquals("INCOMPLETE", turnedOff.completeness(), "a scanner that is turned off still makes the scan partial");
        assertEquals(1, turnedOff.reasons().size());
    }

    @Test void manyRulesFailingOnAScannerThatRanAreCountedNotListed() {
        var assessment = ScanAssessment.of(ScanStatus.DONE, failedEngineWithRules(40, "RAN", "FAILED"), List.of());

        assertEquals(1, assessment.reasons().size());
        assertEquals("40 rules failed, including Rule0, Rule1, Rule2 and 37 more.", assessment.reasons().getFirst());
    }

    @Test void aFewFailedRulesAreStillNamedOneByOne() {
        var assessment = ScanAssessment.of(ScanStatus.DONE, failedEngineWithRules(2, "RAN", "FAILED"), List.of());

        assertEquals(List.of("Rule0 failed.", "Rule1 failed."), assessment.reasons());
    }

    @Test void emptyOrAmbiguousEngineEvidenceCannotEstablishCoverageOrComparison() {
        var empty = new CodeScanExecutionSnapshot(1, 1L, "Fixture", RulePriority.HIGH, List.of(), List.of(), null);
        var duplicate = new CodeScanExecutionSnapshot(1, 1L, "Fixture", RulePriority.HIGH, snapshot("RAN").rules(),
                List.of(snapshot("RAN").engines().getFirst(), snapshot("RAN").engines().getFirst()), null);
        for (var evidence : List.of(empty, duplicate)) {
            assertEquals("UNKNOWN", ScanAssessment.of(ScanStatus.DONE, evidence, List.of()).completeness());
            var report = new RepoScanReport(5, 1, "api", "repo", "main", "commit", "Fixture",
                    List.of(), List.of(), List.of(), 0, evidence).withComparison(RepoScanReport.REPOSITORY_SCOPE, null);
            assertFalse(ScanComparison.assess(report, report).comparable());
        }
    }

    @Test void incompleteProviderCannotBecomeCleanEvenWithSuccessfulLocalEngines() {
        var status = new RemoteAssessmentService.Status("run", "UNAVAILABLE", "Unavailable", "commit", null,
                null, null, 0, 0, false, false, null, 0, Map.of());
        var provider = new ProviderAssessmentReference("fixture", "run", null, status, null, RULE,
                "Policy", RULE.revision(), Map.of(), 0);
        assertEquals("INCOMPLETE", ScanAssessment.of(ScanStatus.DONE, snapshot("RAN"), List.of(provider)).completeness());
    }
    @Test void liveProviderResultCompletesAnEarlierQueuedRepositoryReport() {
        var queued = new RemoteAssessmentService.Status("run", "QUEUED", "Waiting for AWS capacity", "commit", null,
                null, null, 0, 0, false, false, null, 0, Map.of());
        var complete = new RemoteAssessmentService.Status("run", "COMPLETE", null, "commit", null,
                "review", "job", 1, 0, true, true, null, 1, Map.of());
        var stored = new ProviderAssessmentReference("fixture", "run", null, queued, null, RULE,
                "Policy", RULE.revision(), Map.of(), 0);
        var current = new ProviderAssessmentReference("fixture", "run", "manifest", complete, null, RULE,
                "Policy", RULE.revision(), Map.of(), 0);
        var report = new RepoScanReport(5, 1, "api", "repo", "main", "commit", "Fixture",
                List.of(), List.of(), List.of(), 0, snapshot("RAN"), null, List.of(stored));
        assertEquals("INCOMPLETE", ScanAssessment.from(report).completeness());
        assertTrue(ScanAssessment.from(report, List.of(current)).complete());
    }

    @Test void unreadableMetadataPreservesTheSourceProcessingState() {
        var scan = new PullRequestScanEntity();
        scan.setExecutionSnapshotJson(CodeScanExecutionSnapshotCodec.encode(snapshot("RAN")));
        for (String malformed : List.of("{", "null", "[null]")) {
            scan.setProviderSummaryJson(malformed);
            for (var status : ScanStatus.values()) {
                scan.setStatus(status);
                var assessment = ScanAssessment.from(scan);
                assertEquals(ScanAssessment.of(status, null, List.of()).processing(), assessment.processing());
                assertEquals("UNKNOWN", assessment.completeness());
                assertFalse(assessment.reasons().isEmpty());
            }
        }
    }

    @Test void historicalDeploymentSkipExplainsTheNewUiControlWithoutChangingTheReceipt() {
        String reason="AWS canary and Dev readiness gates have not passed";
        var status=new RemoteAssessmentService.Status("old", "UNAVAILABLE",reason,"commit",null,null,null,0,0,true,false,null,0,Map.of());
        assertEquals(reason,status.reason());assertTrue(status.reasonLabel().contains("old requirement has been removed"));assertTrue(status.reasonLabel().contains("start a new scan"));
    }

    @Test void unknownProcessingAndQueueJobsAreNotScanAssessmentClaims() {
        assertEquals("Unknown", StatusPresentationModel.from((ScanStatus) null).getLabel());
        assertEquals("Unknown", StatusPresentationModel.from(ScanAssessment.of(null, null, List.of())).getLabel());
        assertEquals("Completed", StatusPresentationModel.from(AsyncJobStatus.DONE).getLabel());
        assertEquals("Job completed", StatusPresentationModel.from(AsyncJobStatus.DONE).getAccessibleText());
        for (var status : List.of(ScanStatus.FAILED, ScanStatus.IN_PROGRESS, ScanStatus.NOT_STARTED)) {
            assertEquals("INCOMPLETE", ScanAssessment.of(status, snapshot("RAN"), List.of()).completeness());
        }
    }
}
