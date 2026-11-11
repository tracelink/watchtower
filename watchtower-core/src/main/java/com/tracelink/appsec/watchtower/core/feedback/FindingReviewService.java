package com.tracelink.appsec.watchtower.core.feedback;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.UriUtils;
import com.tracelink.appsec.watchtower.core.mvc.PagedResult;
import com.tracelink.appsec.watchtower.core.persistence.*;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.*;

/** Source-free, occurrence-bound review data. Opening this workspace never requests AI. */
@Service
@Transactional(readOnly = true)
public class FindingReviewService {
    private final FindingFeedbackService feedback;
    private final LedgerRepository records;
    private final RepoScanRepository scans;
    private final RepoScanReportService reports;
    @Autowired(required = false) private RemoteAssessmentService remote;

    public FindingReviewService(FindingFeedbackService feedback, LedgerRepository records,
            RepoScanRepository scans, RepoScanReportService reports) {
        this.feedback = feedback; this.records = records; this.scans = scans; this.reports = reports;
    }

    public record Item(String key, String title, String severity, String file, Integer line,
            Long ruleId, String revision, long version, String judgment, String disposition, String explanation) { }
    public record Workspace(String scanType, long scanId, Item selected, String returnUrl,
            boolean bulkAvailable, String limitation, int providerPage) { }
    public record History(String judgment, String disposition, String explanation, String reviewer, long changedAt) { }
    /** JPQL projection avoids loading every finding through an eager parent scan relationship. */
    public record StoredFinding(long id, String title, RulePriority severity, String file, int line,
            Long ruleId, String revision) { }
    private static final String SELECT = "SELECT new com.tracelink.appsec.watchtower.core.feedback.FindingReviewService$StoredFinding"
            + "(v.id,v.violationName,v.severity,v.fileName,v.lineNum,v.ruleIdentity.ruleId,v.ruleIdentity.revision) ";

    public Workspace workspace(String type, long scanId, String key, int providerPage, String returnTo) {
        var occurrence = feedback.resolve(type, scanId, key);
        if (providerPage < 0 || providerPage > 10000) throw invalid("Invalid provider evidence page");
        String canonical = reportUrl(type, scanId);
        if ("repository".equals(type)) {
            var report = report(scanId);
            var local = report.findings().stream().filter(f -> key.equals(f.findingKey())).findFirst();
            if (local.isPresent()) return new Workspace(type, scanId, item(type, scanId, local.get()),
                    safeReturn(returnTo, canonical), true, report.isTruncated()
                    ? "This historical artifact retained only part of the findings. Selection covers retained occurrences." : "", providerPage);
        } else if (key.matches("[0-9]+")) {
            var rows = records.list(StoredFinding.class, SELECT + "FROM " + entity(type)
                    + " v WHERE v.scan.id=?1 AND v.id=?2", 0, 1, scanId, Long.parseLong(key));
            if (rows.isEmpty()) throw missing();
            return new Workspace(type, scanId, item(type, scanId, rows.getFirst()),
                    safeReturn(returnTo, canonical), true, "", providerPage);
        }
        if (remote != null) {
            var finding = remote.findings(type, scanId, providerPage).stream()
                    .filter(f -> key.equals(f.getFeedbackKey())).findFirst().orElseThrow(FindingReviewService::missing);
            var selected = item(type, scanId, key, finding.getTitle(), finding.getSeverity(), finding.getFileName(),
                    finding.getLineNumber(), occurrence.ruleId(), occurrence.revision());
            return new Workspace(type, scanId, selected, safeReturn(returnTo, canonical), false,
                    "This review is bound to one provider occurrence. Return to the report to choose another provider finding.", providerPage);
        }
        throw missing();
    }

    /**
     * The scanner module that produced the reviewed finding, for the page's scanner chip, or null
     * when the scan did not record it (older scans) or the finding is a provider finding.
     */
    public String scannerModule(String type, long scanId, String key) {
        if ("repository".equals(type)) {
            return report(scanId).findings().stream().filter(f -> key.equals(f.findingKey())).findFirst()
                    .map(f -> f.ruleIdentity() == null ? null : f.ruleIdentity().module()).orElse(null);
        }
        if (key == null || !key.matches("[0-9]+")) return null;
        var modules = records.list(String.class, "SELECT v.ruleIdentity.module FROM " + entity(type)
                + " v WHERE v.scan.id=?1 AND v.id=?2", 0, 1, scanId, Long.parseLong(key));
        return modules.isEmpty() ? null : modules.getFirst();
    }

    public PagedResult<Item> items(String type, long scanId, String selectedKey, String search, int page, int size) {
        feedback.resolve(type, scanId, selectedKey);
        bounds(page, size);
        String query = Objects.toString(search, "").trim().toLowerCase(Locale.ROOT);
        if (query.length() > 200) throw invalid("Search must be at most 200 characters");
        if ("repository".equals(type)) {
            var matches = report(scanId).findings().stream().filter(f -> f.findingKey() != null)
                    .filter(f -> (Objects.toString(f.rule(), "") + " " + Objects.toString(f.file(), "") + " " + f.line())
                            .toLowerCase(Locale.ROOT).contains(query)).toList();
            return page(matches.stream().skip((long) page * size).limit(size).map(f -> item(type, scanId, f)).toList(),
                    page, size, matches.size());
        }
        String from = "FROM " + entity(type) + " v WHERE v.scan.id=?1 AND (LOWER(v.violationName) LIKE ?2 ESCAPE '!'"
                + " OR LOWER(v.fileName) LIKE ?2 ESCAPE '!')";
        String pattern = "%" + query.replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%";
        long total = records.scalar(Long.class, "SELECT COUNT(v) " + from, scanId, pattern);
        var rows = records.list(StoredFinding.class, SELECT + from + " ORDER BY v.id", page * size, size, scanId, pattern);
        return page(rows.stream().map(f -> item(type, scanId, f)).toList(), page, size, total);
    }

    public PagedResult<History> history(String type, long scanId, String key, int page, int size) {
        feedback.resolve(type, scanId, key); bounds(page, size);
        String occurrence = FindingFeedbackService.occurrenceKey(type, scanId, key);
        long total = records.scalar(Long.class, "SELECT COUNT(h) FROM FindingFeedbackAuditEntity h WHERE h.occurrenceKey=?1", occurrence);
        var rows = records.list(FindingFeedbackAuditEntity.class,
                "SELECT h FROM FindingFeedbackAuditEntity h WHERE h.occurrenceKey=?1 ORDER BY h.auditId DESC", page * size, size, occurrence);
        return page(rows.stream().map(h -> new History(h.judgment, h.disposition, h.explanation, h.reviewer, h.changedAt)).toList(), page, size, total);
    }

    private Item item(String type, long scanId, StoredFinding f) {
        return item(type, scanId, Long.toString(f.id()), f.title(), f.severity() == null ? "Unknown" : f.severity().getName(),
                f.file(), f.line(), f.ruleId(), f.revision());
    }
    private Item item(String type, long scanId, RepoScanReport.Finding f) {
        return item(type, scanId, f.findingKey(), f.rule(), f.severity(), f.file(), f.line(),
                f.ruleIdentity() == null ? null : f.ruleIdentity().ruleId(), f.ruleIdentity() == null ? null : f.ruleIdentity().revision());
    }
    private Item item(String type, long scanId, String key, String title, String severity, String file, Integer line, Long ruleId, String revision) {
        var saved = records.find(FindingFeedbackEntity.class, FindingFeedbackService.occurrenceKey(type, scanId, key));
        return new Item(key, title, severity, file, line, ruleId, revision, saved == null ? 0 : saved.version,
                saved == null ? "UNKNOWN" : saved.judgment, saved == null ? "ACTION_REQUIRED" : saved.disposition,
                saved == null ? "" : saved.explanation);
    }
    private RepoScanReport report(long scanId) {
        var scan = scans.findById(scanId).orElseThrow(FindingReviewService::missing);
        return reports.getReport(scan).orElseThrow(() -> new ResponseStatusException(HttpStatus.GONE, "Report unavailable"));
    }
    private String reportUrl(String type, long id) {
        return switch (type) {
            case "repository" -> "/reposcan/report/" + id;
            case "pull_request" -> "/scan/report/" + id;
            case "upload" -> "/uploadscan/report/" + UriUtils.encodePathSegment(records.scalar(String.class,
                    "SELECT s.container.ticket FROM UploadScanEntity s WHERE s.id=?1", id), StandardCharsets.UTF_8);
            default -> throw invalid("Unsupported scan type");
        };
    }
    static String safeReturn(String requested, String fallback) {
        if (requested == null || requested.length() > 4096 || requested.contains("\\") || requested.chars().anyMatch(Character::isISOControl)) return fallback;
        try {
            var uri = URI.create(requested);
            if (!uri.isAbsolute() && uri.getRawAuthority() == null && requested.startsWith("/")
                    && !requested.startsWith("//") && uri.getRawPath().equals(fallback)) return requested;
        } catch (IllegalArgumentException malformed) { /* use the canonical report */ }
        return fallback;
    }
    private static String entity(String type) {
        return switch (type) { case "pull_request" -> "PullRequestViolationEntity";
            case "upload" -> "UploadViolationEntity"; default -> throw invalid("Unsupported scan type"); };
    }
    private static void bounds(int page, int size) {
        if (page < 0 || size < 1 || size > 100 || (long) page * size > Integer.MAX_VALUE) throw invalid("Invalid page; choose 1–100 rows");
    }
    private static <T> PagedResult<T> page(List<T> items, int number, int size, long total) {
        return new PagedResult<>(items, number, size, total, (int) Math.ceil((double) total / size));
    }
    private static ResponseStatusException invalid(String reason) { return new ResponseStatusException(HttpStatus.BAD_REQUEST, reason); }
    private static ResponseStatusException missing() { return new ResponseStatusException(HttpStatus.NOT_FOUND, "Finding not available in this scan"); }
}
