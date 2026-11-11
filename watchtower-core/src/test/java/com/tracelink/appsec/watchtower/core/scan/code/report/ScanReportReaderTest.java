package com.tracelink.appsec.watchtower.core.scan.code.report;

import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary.ScannerExecution;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummaryCodec;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.*;

class ScanReportReaderTest {
    @Test void sourceRequiresCompleteUntruncatedLocalEvidenceAndExactCommit() {
        var scans = mock(RepoScanRepository.class); var reports = mock(RepoScanReportService.class);
        var reader = new ScanReportReader(mock(PRScanRepository.class), scans, reports, mock(ScanRegistrationService.class)); var scan = new RepoScanEntity();
        when(scans.findWithRepository(1)).thenReturn(Optional.of(scan));
        var safe = new RepoScanReport.Finding("safe", "High", "src/a.java", 1, "message", "fp", false, false);
        when(reports.getReport(scan)).thenReturn(Optional.of(report(List.of(safe), List.of(), 1)));
        assertTrue(reader.permitsSource("repository", 1, "pinned", "src/a.java"));
        assertFalse(reader.permitsSource("repository", 1, "advanced", "src/a.java"));
        for (Boolean sensitive : Arrays.asList(true, null)) {
            var unknown = new RepoScanReport.Finding("unknown", "High", "src/a.java", 7, "message", "fp", false, sensitive);
            when(reports.getReport(scan)).thenReturn(Optional.of(report(List.of(safe, unknown), List.of(), 2)));
            assertTrue(reader.permitsSource("repository", 1, "pinned", "src/a.java"));
            assertEquals(Set.of(7), reader.secretLines("repository", 1, "src/a.java"));
            assertEquals(Set.of(), reader.secretLines("repository", 1, "src/b.java"));
        }
        when(reports.getReport(scan)).thenReturn(Optional.of(report(List.of(safe), List.of("Scanner failed"), 1)));
        assertFalse(reader.permitsSource("repository", 1, "pinned", "src/a.java"));
        when(reports.getReport(scan)).thenReturn(Optional.of(report(List.of(safe), List.of(), 2)));
        assertFalse(reader.permitsSource("repository", 1, "pinned", "src/a.java"));
    }
    private static ICodeScanner scanner(String executionName, boolean sensitive) {
        var scanner = mock(ICodeScanner.class);
        when(scanner.executionName()).thenReturn(executionName);
        when(scanner.isSensitive()).thenReturn(sensitive);
        return scanner;
    }
    private ScanReportReader readerWithScans(RepoScanEntity scan, ICodeScanner... scanners) {
        var scans = mock(RepoScanRepository.class); var registry = mock(ScanRegistrationService.class);
        when(scans.findWithRepository(1)).thenReturn(Optional.of(scan));
        when(registry.getCodeScanners()).thenReturn(List.of(scanners));
        return new ScanReportReader(mock(PRScanRepository.class), scans, mock(RepoScanReportService.class), registry);
    }
    @Test void secretsAreMaskedOnlyWhenASecretsScannerRanOnThatScan() {
        var secrets = scanner("BetterleaksScanner", true); var style = scanner("PMDScanner", false);
        var ran = new RepoScanEntity();
        ran.setScannerExecutionsJson(ScanExecutionSummaryCodec.encode(List.of(
            new ScannerExecution("PMDScanner", "RAN", 5, null), new ScannerExecution("BetterleaksScanner", "RAN", 5, null))));
        assertTrue(readerWithScans(ran, secrets, style).secretsScannerRan("repository", 1), "a secrets scanner ran");
        var skipped = new RepoScanEntity();
        skipped.setScannerExecutionsJson(ScanExecutionSummaryCodec.encode(List.of(
            new ScannerExecution("PMDScanner", "RAN", 5, null), new ScannerExecution("BetterleaksScanner", "SKIPPED", 0, "off"))));
        assertFalse(readerWithScans(skipped, secrets, style).secretsScannerRan("repository", 1), "it was skipped: nothing was checked");
        var noSecretsModule = new RepoScanEntity();
        noSecretsModule.setScannerExecutionsJson(ScanExecutionSummaryCodec.encode(List.of(new ScannerExecution("PMDScanner", "RAN", 5, null))));
        assertFalse(readerWithScans(noSecretsModule, secrets, style).secretsScannerRan("repository", 1), "only a non-secrets scanner ran");
        assertFalse(readerWithScans(new RepoScanEntity(), secrets, style).secretsScannerRan("repository", 1), "no executions were recorded");
        assertFalse(readerWithScans(ran, style).secretsScannerRan("repository", 1), "no secrets module is registered");
    }
    private RepoScanReport report(List<RepoScanReport.Finding> findings, List<String> errors, int total) {
        return new RepoScanReport(4, 1, "bb", "repo", "main", "pinned", "rules", findings, List.of(), errors, total);
    }
}
