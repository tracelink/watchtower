package com.tracelink.appsec.watchtower.core.rule.workflow;

import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import com.tracelink.appsec.watchtower.core.mvc.PagedResult;
import com.tracelink.appsec.watchtower.core.persistence.*;

/** Paged views of existing review/evidence records. No additional task records are created. */
@Service
@Transactional(readOnly = true)
public class RuleReviewWorkspace {
    private final LedgerRepository records;
    public RuleReviewWorkspace(LedgerRepository records) { this.records = records; }
    public record Review(String id, long ruleId, String revision, String owner, String status,
            String reason, String recommendation, String outcome, long updatedAt, long version,
            String evidenceType, String evidenceId) { }
    public record Evidence(String type, String id, String label, String preview) { }
    public record Audit(String status, String actor, String outcome, long changedAt) { }

    public Review selected(long ruleId, String id) {
        if (id == null) return null;
        var row = records.find(RuleReviewItemEntity.class, UUID.fromString(id).toString());
        if (row == null || row.ruleId != ruleId) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Review unavailable for this rule");
        return view(row);
    }
    public PagedResult<Review> reviews(long ruleId, String revision, String state, String search, int page, int size) {
        bounds(page, size); revision(revision);
        if (!Set.of("all", "pending", "OPEN", "IN_REVIEW", "ACCEPTED", "REJECTED", "CLOSED").contains(state)) throw new IllegalArgumentException("Invalid review state");
        var args = new ArrayList<Object>(); args.add(ruleId);
        String from = "FROM RuleReviewItemEntity r WHERE r.ruleId=?1";
        if (revision == null) from += " AND r.revision IS NULL";
        else { args.add(revision); from += " AND r.revision=?2"; }
        if ("pending".equals(state)) from += " AND r.status IN ('OPEN','IN_REVIEW')";
        else if (!"all".equals(state)) { args.add(state); from += " AND r.status=?" + args.size(); }
        args.add(pattern(search)); int q = args.size();
        from += " AND (LOWER(r.owner) LIKE ?" + q + " ESCAPE '!' OR LOWER(r.reason) LIKE ?" + q + " ESCAPE '!')";
        long total = records.scalar(Long.class, "SELECT COUNT(r) " + from, args.toArray());
        return page(records.list(RuleReviewItemEntity.class, "SELECT r " + from + " ORDER BY r.updatedAt DESC,r.reviewId", page * size, size, args.toArray()).stream().map(this::view).toList(), page, size, total);
    }
    public PagedResult<Audit> audit(long ruleId, String reviewId, int page, int size) {
        selected(ruleId, reviewId); bounds(page, size);
        var rows = records.list(RuleReviewAuditEntity.class, "SELECT a FROM RuleReviewAuditEntity a WHERE a.reviewId=?1 ORDER BY a.auditId DESC", page * size, size, reviewId);
        long total = records.scalar(Long.class, "SELECT COUNT(a) FROM RuleReviewAuditEntity a WHERE a.reviewId=?1", reviewId);
        return page(rows.stream().map(a -> new Audit(a.status, a.actor, a.outcome, a.changedAt)).toList(), page, size, total);
    }
    public PagedResult<Evidence> evidence(long ruleId, String revision, String kind, String search, int page, int size) {
        bounds(page, size); revision(revision);
        var args = new ArrayList<Object>(); args.add(ruleId);
        String where = " WHERE e.ruleId=?1";
        if (revision == null) where += " AND e.revision IS NULL";
        else { args.add(revision); where += " AND e.revision=?2"; }
        args.add(pattern(search)); String p = "?" + args.size();
        return switch (kind) {
            case "finding" -> {
                String from = "FROM FindingFeedbackEntity e" + where + " AND (LOWER(e.explanation) LIKE " + p + " ESCAPE '!' OR LOWER(e.judgment) LIKE " + p + " ESCAPE '!')";
                var rows = records.list(FindingFeedbackEntity.class, "SELECT e " + from + " ORDER BY e.updatedAt DESC,e.occurrenceKey", page * size, size, args.toArray());
                yield page(rows.stream().map(e -> new Evidence(kind, e.occurrenceKey, e.scanType + " scan " + e.scanId + " · " + e.judgment,
                        e.disposition + " · " + e.explanation + " · reviewed by " + e.reviewer)).toList(), page, size, records.scalar(Long.class, "SELECT COUNT(e) " + from, args.toArray()));
            }
            case "case" -> {
                String from = "FROM RuleRegressionCaseEntity e" + where + " AND LOWER(e.fixtureRef) LIKE " + p + " ESCAPE '!'";
                var rows = records.list(RuleRegressionCaseEntity.class, "SELECT e " + from + " ORDER BY e.createdAt DESC,e.caseId", page * size, size, args.toArray());
                yield page(rows.stream().map(e -> new Evidence(kind, e.caseId, e.caseKind + " · " + e.fixtureRef,
                        e.expectedBehavior + " · " + e.engine + " / " + e.language + " · SHA-256 " + e.fixtureHash + " · reference only, not an executed test")).toList(), page, size, records.scalar(Long.class, "SELECT COUNT(e) " + from, args.toArray()));
            }
            case "scan" -> {
                String from = "FROM RuleMetricScanEntity e" + where + " AND LOWER(e.scanType) LIKE " + p + " ESCAPE '!'";
                var rows = records.list(RuleMetricScanEntity.class, "SELECT e " + from + " ORDER BY e.bucketStart DESC,e.scanType,e.scanId,e.identityKey", page * size, size, args.toArray());
                yield page(rows.stream().map(e -> new Evidence(kind, e.scanType + ":" + e.scanId, e.scanType + " scan " + e.scanId,
                        e.findings + " findings · engine " + e.engineStatus + " · per-rule coverage " + e.coverage)).toList(), page, size, records.scalar(Long.class, "SELECT COUNT(e) " + from, args.toArray()));
            }
            case "revision" -> page(revision != null && page == 0 ? List.of(new Evidence(kind, revision, "Selected rule revision", revision)) : List.of(), page, size, revision == null ? 0 : 1);
            default -> throw new IllegalArgumentException("Unsupported evidence kind");
        };
    }
    private Review view(RuleReviewItemEntity r) { return new Review(r.reviewId, r.ruleId, r.revision, r.owner, r.status, r.reason, r.recommendation, r.outcome, r.updatedAt, r.version, r.evidenceType, r.evidenceId); }
    public static void bounds(int page, int size) { if (page < 0 || size < 1 || size > 100 || (long) page * size > Integer.MAX_VALUE) throw new IllegalArgumentException("Choose a valid page with 1–100 rows"); }
    public static String pattern(String search) { String value = Objects.toString(search, "").trim().toLowerCase(Locale.ROOT); if (value.length() > 200) throw new IllegalArgumentException("Search is too long"); return "%" + value.replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%"; }
    public static void revision(String value) { if (value != null && !value.matches("[a-f0-9]{64}")) throw new IllegalArgumentException("Invalid revision"); }
    public static <T> PagedResult<T> page(List<T> items, int page, int size, long total) { return new PagedResult<>(items, page, size, total, (int) Math.ceil((double) total / size)); }
}
