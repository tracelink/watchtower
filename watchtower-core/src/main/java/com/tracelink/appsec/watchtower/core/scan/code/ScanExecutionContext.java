package com.tracelink.appsec.watchtower.core.scan.code;

/** Immutable source identity. A branch name alone is never sufficient for remote execution. */
public record ScanExecutionContext(String executionId, CodeScanType type, long scanId,
        long repositoryId, String apiLabel, String repository, String branch, String commit,
        String pullRequestId, String targetBranch, String baseCommit, String mergeBase) {
    public ScanExecutionContext {
        if (executionId == null || type == null) throw new IllegalArgumentException("Missing execution identity");
    }
}
