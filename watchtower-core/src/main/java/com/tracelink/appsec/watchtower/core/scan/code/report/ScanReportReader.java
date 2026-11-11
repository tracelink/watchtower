package com.tracelink.appsec.watchtower.core.scan.code.report;

import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummaryCodec;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanExecutionSnapshot;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanExecutionSnapshotCodec;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanTimings;
import com.tracelink.appsec.watchtower.core.scan.code.CommitIds;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.*;

/** Common source-free read model for exports and source sensitivity checks. Never fetches SCM. */
@Service
public class ScanReportReader {
    private final PRScanRepository prs;
    private final RepoScanRepository repos;
    private final RepoScanReportService reports;
    private final ScanRegistrationService registry;
    public ScanReportReader(PRScanRepository prs, RepoScanRepository repos, RepoScanReportService reports,
            ScanRegistrationService registry) {
        this.prs = prs; this.repos = repos; this.reports = reports; this.registry = registry;
    }
    @Transactional(readOnly = true)
    public RepoScanReport read(String type, long id) {
        if ("repository".equals(type)) {
            var scan = repos.findWithRepository(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
            return reports.getReport(scan).orElseGet(() -> new RepoScanReport(RepoScanReport.SCHEMA, id,
                scan.getRepository().getApiLabel(), scan.getRepository().getRepoName(), scan.getBranch(), scan.getCommitHash(), scan.getRulesetName(),
                List.of(), List.of(), List.of("Local report unavailable: " + scan.getStatus()), scan.getFindingCount(), null, null, scan.getProviderAssessments()));
        }
        if (!"pull_request".equals(type)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        var scan = prs.findById(Long.valueOf(id)).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        var c = scan.getContainer();
        var findings = scan.getViolations().stream().map(v -> new RepoScanReport.Finding(v.getViolationName(),
            v.getSeverity() == null ? "UNKNOWN" : v.getSeverity().getName(), v.getFileName(), v.getLineNum(), v.getMessage(),
            null, Boolean.TRUE.equals(v.getNewFinding()), reports.isSensitive(v.getViolationName()), v.getRuleIdentity(), v.getEngineFingerprint(),
            v.getEffectiveBlocking(), Long.toString(v.getId()))).toList();
        List<String> errors = new ArrayList<>();
        if (!scan.isPerformanceComplete()) errors.add("Local assessment incomplete");
        if (scan.getError() != null && !scan.getError().isBlank()) errors.add("Local scanner errors recorded; inspect scan status");
        return new RepoScanReport(RepoScanReport.SCHEMA, id, c.getApiLabel(), c.getRepoName(), c.getSourceBranch(), scan.getCommitHash(),
            null, findings, List.of(), errors, findings.size(), CodeScanExecutionSnapshotCodec.decode(scan.getExecutionSnapshotJson()), null, scan.getProviderAssessments());
    }
    /**
     * Source of a file may be shown only when the local report is complete at that exact commit, so
     * every line a secrets scanner flagged is known and can be masked ({@link #secretLines}).
     */
    public boolean permitsSource(String type, long id, String commit, String path) {
        var report = read(type, id);
        return CommitIds.same(commit, report.commitHash()) && report.scannerErrors().isEmpty() && !report.isTruncated();
    }

    /**
     * Whether a secrets scanner really ran on this scan, by the scan's recorded scanner executions and not by what is
     * enabled now. Only then can "secrets are masked" be said: without that scan, no line was flagged to mask.
     */
    @Transactional(readOnly = true)
    public boolean secretsScannerRan(String type, long id) {
        Set<String> secretScanners = new HashSet<>();
        for (var scanner : registry.getCodeScanners()) {
            if (scanner.isSensitive()) secretScanners.add(CodeScanExecutionSnapshot.scannerName(scanner));
        }
        return !secretScanners.isEmpty() && executions(type, id).stream()
            .anyMatch(e -> (e.isRan() || "REUSED".equals(e.status())) && secretScanners.contains(e.scannerName()));
    }
    private List<ScanExecutionSummary.ScannerExecution> executions(String type, long id) {
        if ("repository".equals(type)) {
            var scan = repos.findWithRepository(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
            return ScanExecutionSummaryCodec.decode(scan.getScannerExecutionsJson());
        }
        if (!"pull_request".equals(type)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        var scan = prs.findById(Long.valueOf(id)).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        return PRScanTimings.executions(scan.getScannerTimingsJson(), scan.getScannerExecutionsJson());
    }

    /**
     * @return the 1-based lines of {@code path} that must be masked: every line a local finding
     *         marked sensitive, or whose sensitivity was not recorded, landed on
     */
    public Set<Integer> secretLines(String type, long id, String path) {
        var lines = new TreeSet<Integer>();
        for (var finding : read(type, id).findings()) {
            if (path.equals(finding.file()) && !Boolean.FALSE.equals(finding.sensitive())) {
                lines.add(finding.line());
            }
        }
        return Set.copyOf(lines);
    }
}
