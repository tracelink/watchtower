package com.tracelink.appsec.watchtower.core.scan.code;

import java.util.*;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.feedback.FindingFeedbackService.Occurrence;
import com.tracelink.appsec.watchtower.core.scan.presentation.FindingPresentationModel;

/** Optional provider extension; local scanner/test paths never invoke it. */
public interface RemoteAssessmentService {
    boolean selected(RulesetDto rules);
    void preparePullRequest(PullRequest pr, RulesetDto rules, long startedAt);
    String prepareRepository(ScanExecutionContext context, RulesetDto rules);
    /** Cancel an enlisted child if its local parent cannot reach remote execution. */
    default void cancelRepository(String runId) { }
    default Set<com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.BypassedFinding> bypassFindings(long scanId) { return Set.of(); }
    Optional<ScanExecutionContext> repositoryContext(long scanId);
    /** Legacy queue diagnostic; capacity no longer blocks unrelated local repository scans. */
    default Optional<RepositoryAdmissionBlocker> repositoryAdmissionBlocker() { return Optional.empty(); }
    record RepositoryAdmissionBlocker(long scanId, Status assessment) { }
    List<Status> status(String type, long scanId);
    List<FindingPresentationModel> findings(String type, long scanId, int page);
    Optional<Occurrence> occurrence(String type, long scanId, String key);
    /** Common report/export contract; provider implementations stream one bounded page at a time. */
    default List<com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference> reports(String type, long scanId) { return List.of(); }
    default Object receipt(com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference reference) throws java.io.IOException { return reference; }
    default List<ProviderOccurrence> evidence(com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference reference, int page) throws java.io.IOException { return List.of(); }
    record ProviderOccurrence(String key, com.tracelink.appsec.watchtower.core.scan.code.report.ProviderFindingDetails details,
            List<com.tracelink.appsec.watchtower.core.scan.code.report.ProviderFindingDetails.Location> changedLineAnchors) { }
    record ProgressStep(String name, String status, String createdAt, String updatedAt) { }
    record Status(String id, String state, String reason, String commit, String baseCommit,
            String reviewId, String jobId, int imported, int missing, boolean cleanupComplete,
            boolean complete, Integer providerCap, int pages, Map<String, Integer> nativeSeverityCounts, Map<String, String> receiptFacts, List<ProgressStep> progress) {
        public Status(String id, String state, String reason, String commit, String baseCommit, String reviewId, String jobId, int imported, int missing, boolean cleanupComplete, boolean complete, Integer providerCap, int pages, Map<String,Integer> nativeSeverityCounts) {
            this(id, state, reason, commit, baseCommit, reviewId, jobId, imported, missing, cleanupComplete, complete, providerCap, pages, nativeSeverityCounts, Map.of(), List.of());
        }
        public Status { receiptFacts = receiptFacts == null ? Map.of() : Map.copyOf(receiptFacts); progress = progress == null ? List.of() : List.copyOf(progress); }

        public Status withProviderUrl(String url) {
            var facts=new LinkedHashMap<>(receiptFacts);facts.put("AWS review URL",url);
            return new Status(id,state,reason,commit,baseCommit,reviewId,jobId,imported,missing,cleanupComplete,complete,providerCap,pages,nativeSeverityCounts,facts,progress);
        }
        public String providerUrl() { return receiptFacts.get("AWS review URL"); }
        /** The Watchtower rule that ran this assessment ("Security review"), or null for older receipts. */
        public String ruleName() { return receiptFacts.get("Rule"); }
        public boolean providerDeleted() { return "true".equals(receiptFacts.get("AWS review deleted")); }
        public boolean canDeleteProviderReview() { return "true".equals(receiptFacts.get("Can delete AWS review")); }

        /** Explain historical setup messages without changing the saved assessment receipt. */
        public String reasonLabel() {
            if (reason == null) return null;
            return switch(reason) {
                case "AWS canary and Dev readiness gates have not passed" -> "AWS did not run because deployment approval was missing when this scan started. That old requirement has been removed. Check Scanner modules and select the AWS Security review rule, then start a new scan.";
                case "AWS Security Agent is disabled" -> "AWS did not run because it was disabled in the deployment when this scan started. Use Scanner modules to turn it on, select the AWS Security review rule and start a new scan.";
                case "AWS module is disabled" -> "The AWS scanner is turned off. An administrator can turn it on under Scanner modules.";
                case "Repository has not been approved for source export" -> "AWS did not run because repository permission was missing when this scan started. The separate permission step has been removed. Select the AWS Security review rule and start a new scan.";
                case "AWS operation unavailable (ValidationException); inspect stage and reconcile" -> "AWS reported an invalid request (ValidationException). An administrator must reconcile this earlier attempt; it can hold up later repository scans.";
                default -> reason;
            };
        }

        /** One severity chip of the details dialog. */
        public record SeverityCount(String name, String label, int count) { }
        private static final List<String> SEVERITY_ORDER = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL");
        /** Provider severity counts, worst first, for the dialog's chips; unknown names follow alphabetically. */
        public List<SeverityCount> severityCounts() {
            if (nativeSeverityCounts == null) return List.of();
            return nativeSeverityCounts.entrySet().stream().filter(e -> e.getKey() != null && !e.getKey().isBlank() && e.getValue() != null && e.getValue() > 0)
                .sorted(Comparator.comparingInt((Map.Entry<String, Integer> e) -> {
                    int rank = SEVERITY_ORDER.indexOf(e.getKey().toUpperCase(Locale.ROOT));
                    return rank < 0 ? SEVERITY_ORDER.size() : rank;
                }).thenComparing(Map.Entry::getKey))
                .map(e -> new SeverityCount(e.getKey().toUpperCase(Locale.ROOT),
                    e.getKey().substring(0, 1).toUpperCase(Locale.ROOT) + e.getKey().substring(1).toLowerCase(Locale.ROOT), e.getValue()))
                .toList();
        }

        /** True once the provider reached an end state, whatever that state was. */
        public boolean finished() {
            return complete || switch (state == null ? "" : state.toUpperCase(Locale.ROOT)) {
                case "COMPLETE", "COMPLETED", "PARTIAL", "FAILED", "STOPPED", "CANCELED", "UNAVAILABLE" -> true;
                default -> false;
            };
        }
        /** True while the provider is still working. An uncertain run that needs an operator is not "in progress": it is stuck. */
        public boolean inProgress() {
            return !finished() && !"NEEDS_RECONCILIATION".equalsIgnoreCase(state);
        }
        /** When the provider run was queued, in epoch milliseconds; null for receipts saved before this was recorded. */
        public Long startedAt() { return instant("Started"); }
        /** When the provider run ended, in epoch milliseconds; null while it runs or for older receipts. */
        public Long finishedAt() { return instant("Finished"); }
        private Long instant(String key) {
            String text = receiptFacts.get(key);
            if (text == null) return null;
            try { return java.time.Instant.parse(text).toEpochMilli(); } catch (java.time.format.DateTimeParseException e) { return null; }
        }
        /** Elapsed time start to finish, or so far while it runs (the caller passes now); null when unknown or never started. */
        public String elapsedLabel(long now) {
            Long start = startedAt(), end = finishedAt() != null ? finishedAt() : (finished() ? null : Long.valueOf(now));
            if (start == null || end == null || (finished() && (jobId == null || jobId.isBlank()))) return null;
            return com.tracelink.appsec.watchtower.core.scan.presentation.HomeActivityItem.formatDuration(start, end);
        }
        /** True when {@link #elapsedLabel} is the final time, not a running count. */
        public boolean elapsedIsFinal() { return finishedAt() != null; }
        /** The exported source in words ("25 files"), or null when none was prepared. */
        public String sourceLabel() {
            String files = receiptFacts.get("Source files");
            if (files == null || "0".equals(files)) return null;
            return files + ("1".equals(files) ? " file" : " files");
        }
        /** The exported patch in words ("patch 1.8 KB"); "full source" when the scan has no patch. */
        public String patchLabel() {
            String text = receiptFacts.get("Patch bytes");
            long bytes;
            try { bytes = text == null ? 0 : Long.parseLong(text); } catch (NumberFormatException e) { bytes = 0; }
            if (bytes <= 0) return "full source";
            return bytes < 1024 ? "patch " + bytes + " B" : String.format(Locale.ROOT, "patch %.1f KB", bytes / 1024.0);
        }
        /** The id's first characters ("cr-f692003f"), enough to recognise it; the chip copies the whole id. */
        private static String shortId(String id) { return id == null ? null : id.substring(0, Math.min(11, id.length())); }
        public String shortReviewId() { return shortId(reviewId); }
        public String shortJobId() { return shortId(jobId); }
        /** {@link #elapsedLabel(long)} as of now. */
        public String elapsedLabel() { return elapsedLabel(System.currentTimeMillis()); }
        public String shortCommit() { return commit == null ? null : commit.substring(0, Math.min(7, commit.length())); }
        public String shortBaseCommit() { return baseCommit == null ? null : baseCommit.substring(0, Math.min(7, baseCommit.length())); }

        /** The state in plain words ("Did not run" rather than UNAVAILABLE). */
        public String stateLabel() {
            String code = state == null ? "" : state.toUpperCase(java.util.Locale.ROOT);
            return switch (code) {
                case "COMPLETE", "COMPLETED" -> "Complete";
                case "PARTIAL" -> "Incomplete";
                case "UNAVAILABLE" -> "Did not run";
                case "FAILED" -> "Failed";
                case "STOPPED" -> "Stopped";
                case "" -> "Unknown";
                default -> code.charAt(0) + code.substring(1).toLowerCase(java.util.Locale.ROOT).replace('_', ' ');
            };
        }

        /** The chip tone for {@link #stateLabel()}: success, warning (incomplete), danger (did not finish) or info (running). */
        public String tone() {
            if (complete) {
                return "success";
            }
            String code = state == null ? "" : state.toUpperCase(java.util.Locale.ROOT);
            return switch (code) {
                case "PARTIAL" -> "warning";
                case "UNAVAILABLE", "FAILED", "STOPPED" -> "danger";
                default -> "info";
            };
        }
    }
}
