package com.tracelink.appsec.module.awssecurity;

import jakarta.persistence.*;

/** Compact durable metadata only. Source and provider narratives never enter this table. */
@Entity @Table(name = "aws_security_scan_runs", uniqueConstraints = @UniqueConstraint(columnNames = "execution_key"))
public class AwsSecurityRun {
    public enum Stage { QUEUED, PREPARING, INPUT_READY, CREATING, REVIEW_READY, STARTING, RUNNING, IMPORTING, COMPLETE, PARTIAL, FAILED, CANCELED, UNAVAILABLE }
    @Id @Column(length = 36) public String id;
    @Version public long version;
    @Column(name = "execution_key", nullable = false, length = 64) public String executionKey;
    @Column(name = "parent_type", nullable = false, length = 24) public String parentType;
    @Column(name = "parent_id", nullable = false) public long parentId;
    @Column(name = "repository_id", nullable = false) public long repositoryId;
    @Column(name = "snapshot_json", nullable = false, columnDefinition = "TEXT") public String snapshotJson;
    @Column(name = "setup_requester", length = 255) public String setupRequester;
    @Enumerated(EnumType.STRING) @Column(name = "setup_mode", length = 24) public AwsSecuritySetupMode setupMode;
    @Column(name = "inputs_verified") public boolean inputsVerified;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 24) public Stage stage;
    @Column(length = 36) public String owner;
    public long fence;
    @Column(name = "lease_until") public long leaseUntil;
    @Column(name = "created_at") public long createdAt;
    @Column(name = "due_at") public long dueAt;
    @Column(name = "deadline_at") public long deadlineAt;
    @Column(name = "terminal_at") public long terminalAt;
    @Column(name = "dispatch_pending") public boolean dispatchPending;
    @Column(name = "stop_requested") public boolean stopRequested;
    @Column(name = "needs_reconciliation") public boolean needsReconciliation;
    @Column(name = "provider_terminal") public boolean providerTerminal;
    @Column(name = "provider_deleted") public boolean providerDeleted;
    /** True when this run uses its repository's shared AWS review (new pull request and repository runs); setup tests keep their own. */
    @Column(name = "shared_review") public boolean sharedReview;
    /** When the job start was last sent, so an uncertain start is only judged "never happened" after a grace period. */
    @Column(name = "start_attempt_at") public Long startAttemptAt;
    @Column(name = "review_id", length = 128) public String reviewId;
    @Column(name = "job_id", length = 128) public String jobId;
    @Column(name = "provider_status", length = 64) public String providerStatus;
    @Column(name = "status_reason", length = 256) public String statusReason;
    @Column(name = "source_key", length = 255) public String sourceKey;
    @Column(name = "source_version", length = 1024) public String sourceVersion;
    @Column(name = "source_sha", length = 64) public String sourceSha;
    @Column(name = "source_bytes") public long sourceBytes;
    @Column(name = "source_files") public int sourceFiles;
    @Column(name = "diff_key", length = 255) public String diffKey;
    @Column(name = "diff_version", length = 1024) public String diffVersion;
    @Column(name = "diff_sha", length = 64) public String diffSha;
    @Column(name = "source_index_key", length = 255) public String sourceIndexKey;
    @Column(name = "diff_index_key", length = 255) public String diffIndexKey;
    @Column(name = "diff_bytes") public long diffBytes;
    @Column(name = "cleanup_complete") public boolean cleanupComplete;
    @Column(name = "cleanup_attempts") public int cleanupAttempts;
    @Column(name = "artifact_key", length = 255) public String artifactKey;
    @Column(name = "aggregate_published") public boolean aggregatePublished;
    @Column(name = "scm_attempted") public boolean scmAttempted;
    @Column(name = "imported_count") public int importedCount;
    @Column(name = "missing_count") public int missingCount;
    @Column(name = "mapper_version", length = 64) public String mapperVersion;
    @Column(name = "job_receipt_json", columnDefinition = "TEXT") public String jobReceiptJson;
    @Column(name = "import_attempts") public int importAttempts;
    @Column(name = "omitted_count") public int omittedCount;
    @Column(name = "artifact_pages") public int artifactPages;
    @Column(name = "failure_count") public long failureCount;
    @Column(name = "throttle_count") public long throttleCount;
    @ElementCollection(fetch = FetchType.EAGER) @CollectionTable(name = "aws_security_severity_counts", joinColumns = @JoinColumn(name = "run_id"))
    @MapKeyColumn(name = "severity", length = 24) @Column(name = "finding_count")
    public java.util.Map<String, Integer> nativeSeverityCounts = new java.util.HashMap<>();
    @ElementCollection(fetch = FetchType.EAGER) @CollectionTable(name = "aws_security_validation_counts", joinColumns = @JoinColumn(name = "run_id"))
    @MapKeyColumn(name = "validation", length = 128) @Column(name = "finding_count")
    public java.util.Map<String, Integer> validationCounts = new java.util.HashMap<>();
    public com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference reference() {
        var snapshot = AwsSecuritySnapshot.decode(snapshotJson); var c = snapshot.context();
        var facts = new java.util.TreeMap<String,String>();
        facts.put("Repository", java.util.Objects.toString(c.repository(),"Unknown repository")); facts.put("Scan", parentType+" / "+parentId);
        facts.put("Execution stage", stage.name());
        // When the review was queued and when it ended, so the report can show how long AWS really took (ISO-8601, UTC).
        if (createdAt > 0) facts.put("Started", java.time.Instant.ofEpochMilli(createdAt).toString());
        if (terminalAt > 0 && (providerTerminal || finished())) facts.put("Finished", java.time.Instant.ofEpochMilli(terminalAt).toString());
        facts.put("AWS review deleted", Boolean.toString(providerDeleted));
        // A shared review belongs to every scan of the repository, so deleting it for one scan would break the others.
        facts.put("Can delete AWS review", Boolean.toString(finished()&&cleanupComplete&&providerTerminal&&!needsReconciliation&&reviewId!=null&&!providerDeleted&&!sharedReview));
        if (sharedReview) facts.put("AWS review shared", "Yes: one review per repository, one job per scan");
        facts.put("Mode", "pull_request".equals(parentType) ? "Full pinned source + exact PR patch (S3)" : "Full pinned source (S3)");
        facts.put("Source SHA-256", java.util.Objects.toString(sourceSha, "Not prepared")); facts.put("Source bytes", Long.toString(sourceBytes)); facts.put("Source files", Integer.toString(sourceFiles));
        facts.put("Patch SHA-256", java.util.Objects.toString(diffSha, "Not applicable or not prepared")); facts.put("Patch bytes", Long.toString(diffBytes));
        // Where the uploaded inputs were put, so a failed review can be traced in S3 or CloudTrail without reading code.
        String bucket = snapshot.profile().bucket();
        facts.put("Source in S3", sourceKey == null ? "Not uploaded" : "s3://" + bucket + "/" + sourceKey);
        facts.put("Patch in S3", diffKey == null ? "Not applicable or not uploaded" : "s3://" + bucket + "/" + diffKey);
        facts.put("S3 inputs removed", cleanupComplete ? "Yes" : "No");
        facts.put("Account", snapshot.profile().account()); facts.put("Region", snapshot.profile().region()); facts.put("Agent Space", snapshot.profile().spaceId());
        if (snapshot.ruleName() != null) facts.put("Rule", snapshot.ruleName());
        facts.put("Policy revision", snapshot.policyRevision()); facts.put("Mapper", java.util.Objects.toString(mapperVersion, "Not recorded; consult per-finding evidence"));
        facts.put("Requested validation / remediation", "DISABLED / DISABLED"); facts.put("Provider engine / requirements revision", "UNKNOWN / NOT_EXPOSED");
        facts.put("Comparison", "NOT_ESTABLISHED: disappearance is not a verified fix");
        facts.put("Export exclusions", ".git, .svn, dependency/build directories, .aws, .ssh, .env*, keys/certificates and selected archive/binary extensions; see full manifest");
        var job = AwsSecurityJobReceipt.decode(jobReceiptJson);
        var progress = job == null ? java.util.List.<com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService.ProgressStep>of() : job.steps().stream()
            .map(step -> new com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService.ProgressStep(step.name(), step.status(), step.createdAt(), step.updatedAt())).toList();
        if (job != null) { facts.put("Provider error code", java.util.Objects.toString(job.errorCode(), "Not reported")); facts.put("Retained progress steps", progress.size() + " / " + job.returnedSteps()); }
        var status = new com.tracelink.appsec.watchtower.core.scan.code.RemoteAssessmentService.Status(id, needsReconciliation ? "NEEDS_RECONCILIATION" : stage.name(), statusReason,
            c.commit(), c.baseCommit(), reviewId, jobId, importedCount, missingCount, cleanupComplete,
            stage == Stage.COMPLETE && artifactKey != null, "pull_request".equals(parentType) ? 30 : null, artifactPages, java.util.Map.copyOf(nativeSeverityCounts), facts, progress);
        return new com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference("AWS_SECURITY_AGENT", id, artifactKey, status, c, snapshot.rule(), snapshot.ruleName(), snapshot.policyRevision(), validationCounts, omittedCount);
    }
    public boolean finished() { return switch (stage) { case COMPLETE, PARTIAL, FAILED, CANCELED, UNAVAILABLE -> true; default -> false; }; }
    public boolean remotePossible() { return reviewId != null || stage == Stage.CREATING || stage == Stage.STARTING || jobId != null; }
}
