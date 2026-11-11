package com.tracelink.appsec.module.awssecurity;

import java.util.*;
import java.util.function.Consumer;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.tracelink.appsec.module.awssecurity.AwsSecurityRun.Stage;
import com.tracelink.appsec.watchtower.core.rule.RuleRevision;

/** Short JPA transactions only; no remote calls while holding locks. */
@Service
public class AwsSecurityPersistence {
    private final AwsSecurityRunRepository runs;
    private final AwsSecurityPermitRepository permits;
    private final AwsSecurityCapacity capacity;
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private AwsSecurityAuditRepository audit;
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository prScans;
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository repoScans;
    private void project(AwsSecurityRun run) {
        if (prScans != null && "pull_request".equals(run.parentType)) prScans.updateProviderSummary(run.parentId,
            com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference.encode(java.util.List.of(run.reference())));
        if (repoScans != null && "repository".equals(run.parentType)) repoScans.findById(run.parentId).ifPresent(scan ->
            scan.setProviderSummaryJson(com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference.encode(java.util.List.of(run.reference()))));
    }
    @org.springframework.beans.factory.annotation.Autowired
    public AwsSecurityPersistence(AwsSecurityRunRepository runs, AwsSecurityPermitRepository permits, AwsSecurityCapacity capacity) {
        this.runs = runs; this.permits = permits; this.capacity = capacity;
    }
    AwsSecurityPersistence(AwsSecurityRunRepository runs, AwsSecurityPermitRepository permits) {
        this(runs, permits, new AwsSecurityCapacity(1));
    }
    @Transactional
    public AwsSecurityRun enlistSetup(AwsSecuritySnapshot snapshot, long seconds, String actor, String requestKey, AwsSecuritySetupMode mode) {
        permits.locked();
        String key=RuleRevision.definition("aws-setup-request","v1").field("actor",actor).field("request",requestKey).hash();
        var previous=runs.findByExecutionKey(key);
        if(previous.isPresent()){
            if(previous.get().setupMode!=mode)throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.CONFLICT,"This request already selected a different test");
            return previous.get();
        }
        if(runs.existsByParentTypeAndStageNotIn("setup", java.util.Set.of(Stage.COMPLETE,Stage.PARTIAL,Stage.FAILED,Stage.CANCELED,Stage.UNAVAILABLE)))
            throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.CONFLICT,"A setup test is already active. Open test history to follow it.");
        var run=new AwsSecurityRun();run.id=UUID.randomUUID().toString();run.executionKey=key;run.parentType="setup";
        run.snapshotJson=snapshot.encode();run.setupRequester=actor;run.setupMode=mode;run.stage=Stage.QUEUED;
        run.createdAt=System.currentTimeMillis();run.dueAt=run.createdAt;run.deadlineAt=run.createdAt+seconds*1000;run.dispatchPending=true;
        var saved=runs.saveAndFlush(run);
        if(audit!=null)audit.save(new AwsSecurityAudit("setup-test-approved",actor,run.id));
        return saved;
    }
    @Transactional
    public AwsSecurityRun enlist(AwsSecuritySnapshot snapshot, long reviewSeconds, String unavailable) {
        return enlist(snapshot, reviewSeconds, unavailable, null);
    }
    @Transactional
    public AwsSecurityRun enlist(AwsSecuritySnapshot snapshot, long reviewSeconds, String unavailable, java.util.function.LongSupplier parent) {
        permits.locked(); // Serializes creation as well as admission across pods.
        var context = snapshot.context();
        String key = RuleRevision.definition("aws-assessment", "v1").field("execution", context.executionId())
            .field("type", context.type().name()).field("profile", snapshot.profile().revision()).field("policy", snapshot.policyRevision()).hash();
        var existing = runs.findByExecutionKey(key); if (existing.isPresent()) return existing.get();
        if (parent != null) {
            long parentId = parent.getAsLong();
            context = new com.tracelink.appsec.watchtower.core.scan.code.ScanExecutionContext(context.executionId(), context.type(), parentId,
                context.repositoryId(), context.apiLabel(), context.repository(), context.branch(), context.commit(), context.pullRequestId(),
                context.targetBranch(), context.baseCommit(), context.mergeBase());
            snapshot = new AwsSecuritySnapshot(context, snapshot.profile(), snapshot.rule(), snapshot.ruleName(), snapshot.blockingLevel(), snapshot.policyRevision());
        }
        AwsSecurityRun run = new AwsSecurityRun(); run.id = UUID.randomUUID().toString(); run.executionKey = key;
        run.parentId = context.scanId(); run.parentType = context.type().getTypeName(); run.repositoryId = context.repositoryId();
        run.snapshotJson = snapshot.encode(); run.createdAt = System.currentTimeMillis(); run.dueAt = run.createdAt;
        run.deadlineAt = run.createdAt + reviewSeconds * 1000;
        run.stage = unavailable == null ? Stage.QUEUED : Stage.UNAVAILABLE;
        run.statusReason = unavailable; run.dispatchPending = unavailable == null && "pull_request".equals(run.parentType);
        if (unavailable != null) { run.terminalAt = run.createdAt; run.cleanupComplete = true; run.dueAt = Long.MAX_VALUE; }
        var saved = runs.saveAndFlush(run); project(saved);
        if (audit != null) audit.save(new AwsSecurityAudit("assessment-enlisted", "scan-trigger", run.id));
        return saved;
    }
    @Transactional
    public Optional<AwsSecurityRun> claim(String id, String owner, long now) {
        var control = permits.locked(); // Serializes slot assignment and setting changes across pods.
        var run = runs.locked(id).orElse(null);
        if (run == null || run.leaseUntil > now && !owner.equals(run.owner)) return Optional.empty();
        if (!run.finished()) {
            var slots = permits.findAllByOrderByIdAsc();
            var assigned = slots.stream().filter(p -> id.equals(p.runId)).findFirst();
            if (assigned.isEmpty() && ("repository".equals(run.parentType)||"setup".equals(run.parentType))
                    && runs.existsByParentTypeAndStage("pull_request", Stage.QUEUED)) {
                if (run.stage == Stage.QUEUED) { run.statusReason = "Waiting for AWS capacity; PR reviews have priority"; project(run); }
                return Optional.empty();
            }
            if (assigned.isEmpty()) {
                int limit = capacity.limit(control);
                if (slots.stream().filter(p -> p.runId != null).count() >= limit) {
                    if (run.stage == Stage.QUEUED) { run.statusReason = "Waiting for AWS capacity"; project(run); }
                    return Optional.empty();
                }
                var free = slots.stream().filter(p -> p.id <= limit && p.runId == null).findFirst();
                if (free.isEmpty()) throw new IllegalStateException("AWS permit migration missing a configured slot");
                free.get().runId = id;
                // The review timeout starts when AWS capacity is granted, not while queued.
                if (run.stage == Stage.QUEUED) run.deadlineAt = now + Math.max(0, run.deadlineAt - run.createdAt);
            }
            if (run.stage == Stage.QUEUED && run.statusReason != null && run.statusReason.startsWith("Waiting for AWS capacity")) {
                run.statusReason = null; project(run);
            }
        }
        run.owner = owner; run.fence++; run.leaseUntil = now + 180_000;
        return Optional.of(runs.saveAndFlush(run));
    }
    @Transactional
    public AwsSecurityRun update(String id, String owner, long fence, Consumer<AwsSecurityRun> change) {
        var run = runs.locked(id).orElseThrow();
        requireOwned(run, owner, fence);
        boolean cleaned = run.cleanupComplete, retired = run.providerDeleted;
        change.accept(run); project(run); run.leaseUntil = System.currentTimeMillis() + 180_000;
        if (audit != null && !cleaned && run.cleanupComplete) audit.save(new AwsSecurityAudit("inputs-deleted", "recovery-worker", run.id));
        if (audit != null && !retired && run.providerDeleted) audit.save(new AwsSecurityAudit("provider-retired", "recovery-worker", run.id));
        return runs.saveAndFlush(run);
    }
    public static void requireOwned(AwsSecurityRun run, String owner, long fence) {
        if (!Objects.equals(owner, run.owner) || run.fence != fence || run.leaseUntil < System.currentTimeMillis())
            throw new LostOwnership();
    }
    @Transactional
    public void release(String id, String owner, long fence) {
        permits.locked(); var run = runs.locked(id).orElseThrow(); requireOwned(run, owner, fence);
        // A local failure/deadline alone must never release an uncertain remote job.
        if (run.finished() && (!run.remotePossible() || run.providerTerminal)) {
            permits.findAllByOrderByIdAsc().stream().filter(p -> id.equals(p.runId)).forEach(p -> p.runId = null);
        }
        run.owner = null; run.leaseUntil = 0;
    }
    @Transactional
    public void requestStop(String id) { var run = runs.locked(id).orElseThrow(); run.stopRequested = true; run.dueAt = 0; }
    @Transactional
    public void scheduleRecovery(String id) { var run = runs.locked(id).orElseThrow(); run.dueAt = 0; }
    @Transactional
    public void scheduleCapacityRetry(String id) {
        var run = runs.locked(id).orElseThrow();
        if (!run.finished()) run.dueAt = System.currentTimeMillis() + 30_000;
    }
    @Transactional
    public void dispatchRecorded(String id) { var run = runs.locked(id).orElseThrow(); run.dispatchPending = false; run.dueAt = System.currentTimeMillis() + 300_000; }
    @Transactional
    public void retryImport(String id) {
        var run = runs.locked(id).orElseThrow();
        if (run.providerDeleted || !run.providerTerminal || !Set.of("COMPLETED", "FAILED", "STOPPED").contains(Objects.toString(run.providerStatus, "")) || run.artifactKey != null)
            throw new IllegalStateException("Only unpublished terminal imports can be retried");
        run.stage = Stage.IMPORTING; run.importAttempts = 0; run.dueAt = 0; project(run);
    }
    public static class LostOwnership extends IllegalStateException { public LostOwnership() { super("AWS execution ownership lost"); } }
}
