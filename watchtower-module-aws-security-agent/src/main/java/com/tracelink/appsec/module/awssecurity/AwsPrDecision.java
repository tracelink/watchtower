package com.tracelink.appsec.module.awssecurity;

import java.util.*;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.ActiveBypass;

/** Threshold projection only. Confidence never changes severity, but only a high-confidence finding can block. */
public final class AwsPrDecision {
    public enum FailurePolicy { UNDECIDED, KEEP_INCOMPLETE, PASS_ON_ERROR }
    public enum Decision { BLOCK, ALLOW, INCOMPLETE }
    private AwsPrDecision() { }
    /** High confidence, or none reported: a finding whose confidence cannot be read is not assumed to be a weak one. */
    static boolean confident(com.tracelink.appsec.watchtower.core.scan.code.report.ProviderFindingDetails details) {
        return details.confidence() == null || "HIGH".equals(details.confidence());
    }
    /**
     * Why a finding that reaches the blocking level still does not block: AWS is not highly confident about it.
     * Null when confidence is not the reason (it is confident, or the finding is below the level anyway).
     */
    static String notBlockingNote(com.tracelink.appsec.watchtower.core.scan.code.report.ProviderFindingDetails details,
            AwsSecuritySnapshot snapshot) {
        var priority = details.legacyPriority();
        boolean reachesLevel = priority != null && snapshot.blockingLevel() != null && priority.compareTo(snapshot.blockingLevel()) <= 0;
        if (confident(details) || !reachesLevel) return null;
        String level = details.confidence();
        return "not blocking: AWS confidence is " + level.charAt(0) + level.substring(1).toLowerCase(Locale.ROOT) + ", High is needed";
    }
    public static Decision decide(AwsSecuritySnapshot snapshot, List<AwsSecurityArtifact.Occurrence> findings,
            boolean complete, boolean localBlocking, ActiveBypass bypass, FailurePolicy failurePolicy) {
        boolean unresolved = !complete;
        boolean block = localBlocking;
        for (var finding : findings) {
            // Only a finding AWS is highly confident about can block; the rest are reported on the pull request but never block it.
            if (!confident(finding.details())) continue;
            var severity = finding.details().legacyPriority();
            if (severity == null || finding.changedLineAnchors().isEmpty()) { unresolved = true; continue; }
            if (snapshot.blockingLevel() == null || severity.compareTo(snapshot.blockingLevel()) > 0) continue;
            if (bypass == null || finding.changedLineAnchors().stream().anyMatch(l -> !bypass.covers(snapshot.ruleName(), l.file()))) block = true;
        }
        if (block) return Decision.BLOCK;
        // PASS_ON_ERROR affects terminal provider failures only, never unresolved severity/relevance.
        if (unresolved) return Decision.INCOMPLETE;
        return Decision.ALLOW;
    }
}
