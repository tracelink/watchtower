package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report;

import java.util.*;

/** A delta is a claim about equivalent assessment, not merely absence from an artifact. */
public record ScanComparison(boolean comparable, Long baselineScanId, Integer newCount,
        Integer fixedCount, boolean fixedSampleTruncated, List<String> reasons) {
    public ScanComparison { reasons = List.copyOf(reasons); }
    public static ScanComparison unavailable(Long baseline, String reason) {
        return new ScanComparison(false, baseline, null, null, false, List.of(reason));
    }
    public static ScanComparison assess(RepoScanReport current, RepoScanReport previous) {
        if (previous == null) return unavailable(null, "FIRST_SCAN: no baseline report is available");
        var reasons = new ArrayList<String>();
        if (!Objects.equals(current.apiLabel(), previous.apiLabel()) || !Objects.equals(current.repository(), previous.repository()) ||
                !Objects.equals(current.branch(), previous.branch())) reasons.add("DIFFERENT_SCOPE: repository or branch differs");
        if (current.scope() == null || previous.scope() == null) reasons.add("UNKNOWN_SCOPE: historical scan scope was not recorded");
        else if (!current.scope().equals(previous.scope())) reasons.add("CHANGED_SCOPE: source selection differs");
        if (previous.isTruncated()) reasons.add("TRUNCATED_BASELINE: missing baseline findings cannot establish new or fixed totals");
        var now = current.executionSnapshot();var before = previous.executionSnapshot();
        if (now == null || before == null) reasons.add("MISSING_EXECUTION: engine and rule coverage is unknown");
        else {
            if (!now.hasSuccessfulExecution() || !before.hasSuccessfulExecution()
                    || !com.tracelink.appsec.watchtower.core.scan.presentation.ScanAssessment.from(current).complete()
                    || !com.tracelink.appsec.watchtower.core.scan.presentation.ScanAssessment.from(previous).complete())
                reasons.add("INCOMPLETE_EXECUTION: a required engine failed, skipped or has unknown coverage");
            if (!now.fingerprint().equals(before.fingerprint())) reasons.add("CHANGED_COVERAGE: rule revisions, engine identities or configuration differ");
        }
        if (!current.scannerErrors().isEmpty() || !previous.scannerErrors().isEmpty()) reasons.add("SCANNER_ERRORS: required assessment was incomplete");
        if (!current.providerComplete() || !previous.providerComplete()) reasons.add("INCOMPLETE_PROVIDER: required provider assessment did not complete");
        // Native provider fingerprints do not currently establish cross-run remediation.
        if (!current.providerAssessments().isEmpty() || !previous.providerAssessments().isEmpty()) reasons.add("PROVIDER_COMPARISON_UNVERIFIED: cross-run provider identity is not established");
        return new ScanComparison(reasons.isEmpty(), previous.scanId(), null, null, false, reasons);
    }
}
