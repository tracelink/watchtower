package com.tracelink.appsec.module.awssecurity;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import org.springframework.stereotype.Service;
import org.apache.commons.io.FileUtils;
import com.tracelink.appsec.module.awssecurity.AwsSecurityRun.Stage;
import com.tracelink.appsec.watchtower.core.module.ModuleControlService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.*;

/** One durable state transition at a time, with ambiguous mutation intents left intact. */
@Service
public class AwsSecurityScanCoordinator {
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(AwsSecurityScanCoordinator.class);
    /** AWS refuses a differential input unless the object key ends in .patch ("diffSource.s3Uri must point to a .patch file"). */
    static final String DIFF_OBJECT = "changes.patch";
    /** How long a scan waits before asking again when another scan of its repository is setting up the shared review. */
    private static final long LOCK_WAIT_MS = 5_000;
    /** A job that does not show up this long after its start was sent is treated as never started (the job list may lag). */
    private static final long START_GRACE_MS = 3 * 60_000L;
    /** The provider's clock may differ from ours a little. */
    private static final long CLOCK_SKEW_MS = 2 * 60_000L;
    /** The request fields whose names may appear in a failure reason. */
    private static final Set<String> SCHEMA_FIELDS = Set.of("title", "agentSpaceId", "assets", "serviceRole", "logConfig",
        "validationMode", "codeRemediationStrategy", "codeReviewId", "diffSource");
    private static final java.util.regex.Pattern SCHEMA_PATH =
        java.util.regex.Pattern.compile("[A-Za-z][A-Za-z0-9_]{0,40}(\\.[A-Za-z][A-Za-z0-9_]{0,40}|\\[\\d{1,4}\\]){0,5}");
    private final AwsSecurityPersistence persistence;
    private final AwsSecurityRunRepository runs;
    private final AwsSecurityClientGateway gateway;
    private final AwsSecurityInputStore inputs;
    private final AwsSecurityImporter importer;
    private final ApiIntegrationService integrations;
    private final AwsSecuritySettings settings;
    private final ModuleControlService controls;
    private final AwsSecurityRepositorySettingsRepository repositories;
    private final AwsSecurityRepoReviews repoReviews;
    private AwsSecuritySetupAccess setupAccess;
    @org.springframework.beans.factory.annotation.Autowired
    void setSetupAccess(AwsSecuritySetupAccess access){this.setupAccess=access;}
    public AwsSecurityScanCoordinator(AwsSecurityPersistence persistence, AwsSecurityRunRepository runs,
            AwsSecurityClientGateway gateway, AwsSecurityInputStore inputs, AwsSecurityImporter importer,
            ApiIntegrationService integrations, AwsSecuritySettings settings, ModuleControlService controls,
            AwsSecurityRepositorySettingsRepository repositories, AwsSecurityRepoReviews repoReviews) {
        this.persistence = persistence; this.runs = runs; this.gateway = gateway; this.inputs = inputs;
        this.importer = importer; this.integrations = integrations; this.settings = settings; this.controls = controls; this.repositories = repositories; this.repoReviews = repoReviews;
    }
    public boolean run(String id, Runnable receiptHeartbeat, long receiptDeadline) {
        String owner = UUID.randomUUID().toString();
        var claimed = persistence.claim(id, owner, System.currentTimeMillis()); if (claimed.isEmpty()) return false;
        var run = claimed.get(); long fence = run.fence;
        var lease = Executors.newSingleThreadScheduledExecutor();
        var lost = new java.util.concurrent.atomic.AtomicBoolean();
        var heartbeat = lease.scheduleAtFixedRate(() -> {
            try { receiptHeartbeat.run(); persistence.update(id, owner, fence, r -> { }); }
            catch (RuntimeException e) { lost.set(true); }
        }, 30, 30, TimeUnit.SECONDS);
        try {
            while (!Thread.currentThread().isInterrupted() && !lost.get()) {
                run = runs.findById(id).orElseThrow(); AwsSecurityPersistence.requireOwned(run, owner, fence);
                if (System.currentTimeMillis() > receiptDeadline) {
                    persistence.update(id, owner, fence, r -> { r.stopRequested = true; r.needsReconciliation = true; r.dueAt = 0; }); return true;
                }
                if (run.finished()) { cleanup(run, owner, fence); return true; }
                boolean waiting = step(run, owner, fence);
                run = runs.findById(id).orElseThrow();
                if (waiting) return true; // Another scan holds the repository's review; the saved due time wakes this one.
                if (run.needsReconciliation) return true; // Permit remains held; recovery owns future attempts.
                if (run.stage == Stage.RUNNING) {
                    // AWS owns the long-running job. Persist the next poll and release this
                    // worker/SQS receipt; the durable queue wakes it without holding a thread.
                    if (Thread.currentThread().isInterrupted()) return false;
                    persistence.update(id, owner, fence, r -> r.dueAt = System.currentTimeMillis()
                        + 15000 + ThreadLocalRandom.current().nextInt(5000));
                    return true;
                }
            }
            return false;
        } catch (AwsSecurityPersistence.LostOwnership e) { return false;
        } catch (Exception e) {
            // The person sees a class name and a stage; the cause goes to the server log only.
            LOG.warn("AWS run {} failed: {}", id, e.getClass().getName(), e);
            // Persist only a stage/code, never provider exception messages or source-bearing response bodies.
            try { persistence.update(id, owner, fence, r -> {
                String code = e instanceof software.amazon.awssdk.awscore.exception.AwsServiceException aws && aws.awsErrorDetails() != null
                    ? AwsSecurityFindingMapper.atom(aws.awsErrorDetails().errorCode()) : null;
                r.failureCount++;
                if (throttled(e)) r.throttleCount++;
                // Before the provider is contacted the failure is ours (source preparation), not AWS's.
                boolean beforeProvider = code == null && (r.stage == Stage.QUEUED || r.stage == Stage.PREPARING);
                r.statusReason = beforeProvider
                    ? sourcePreparationReason(e)
                    : "AWS operation unavailable" + (code == null ? "" : " (" + code + ")") + "; inspect stage and reconcile";
                r.dueAt = System.currentTimeMillis() + 60000;
                if (r.stage == Stage.CREATING || r.stage == Stage.STARTING || r.stage == Stage.RUNNING) r.needsReconciliation = true;
                else if (r.stage == Stage.IMPORTING && r.providerTerminal && e instanceof AwsSecurityImporter.ImportLimitExceeded limit) {
                    r.stage = Stage.PARTIAL; r.importedCount = 0; r.missingCount = limit.returned; r.omittedCount = limit.returned;
                    r.statusReason = "Import bound " + limit.bound + ": " + limit.returned + " returned IDs; no evidence published";
                }
                else if (r.stage == Stage.IMPORTING && r.providerTerminal && ++r.importAttempts >= 3) {
                    r.stage = Stage.FAILED; r.terminalAt = System.currentTimeMillis();
                    r.statusReason = "Evidence import failed after three attempts; retry unpublished import after recovery";
                }
                else if (r.stage != Stage.IMPORTING && !r.finished()) { r.stage = Stage.FAILED; r.terminalAt = System.currentTimeMillis(); }
            }); } catch (AwsSecurityPersistence.LostOwnership ignored) { }
            return true;
        } finally {
            heartbeat.cancel(false); lease.shutdownNow();
            releaseRepositoryLock(id);
            try { persistence.release(id, owner, fence); } catch (AwsSecurityPersistence.LostOwnership ignored) { }
        }
    }
    /** One transition of the run. True means it cannot proceed yet and has saved when to be woken. */
    private boolean step(AwsSecurityRun run, String owner, long fence) throws IOException {
        var snapshot = AwsSecuritySnapshot.decode(run.snapshotJson); var p = snapshot.profile();
        // The deployed clients are region-bound. Preserve identity and capacity if the installation is rebound.
        if (!settings.profile().revision().equals(p.revision()) && run.remotePossible()) {
            change(run, owner, fence, r -> { r.needsReconciliation = true; r.dueAt = System.currentTimeMillis() + 60000;
                r.statusReason = "Restore the frozen deployment profile before provider reconciliation"; }); return false;
        }
        boolean permitted = "setup".equals(run.parentType)
            ? setupAccess!=null && setupAccess.allowed(run.setupRequester)
            : controls.enabled(AwsSecurityModule.NAME);
        boolean stop = run.stopRequested || !permitted || System.currentTimeMillis() >= run.deadlineAt;
        if (stop && !run.remotePossible()) {
            change(run, owner, fence, r -> { r.stage = Stage.CANCELED; r.terminalAt = System.currentTimeMillis(); r.statusReason = "Stopped before provider submission"; }); return false;
        }
        switch (run.stage) {
            case QUEUED, PREPARING -> prepare(run, owner, fence);
            case INPUT_READY -> {
                if (run.sharedReview) return sharedReview(run, owner, fence, p);
                change(run, owner, fence, r -> r.stage = Stage.CREATING);
                String review;
                try { review = gateway.create(p, AwsSecurityIdentity.reviewTitle(run), uri(p, run.sourceKey)); }
                catch (software.amazon.awssdk.services.securityagent.model.ValidationException rejected) {
                    rejected(run, owner, fence, "review creation", rejected); return false;
                }
                if (review == null || review.isBlank()) throw new IOException("Review id unavailable");
                change(run, owner, fence, r -> { r.reviewId = review; r.stage = Stage.REVIEW_READY; });
            }
            case CREATING -> {
                if (run.sharedReview) return sharedReview(run, owner, fence, p);
                var review = gateway.reconcileCreate(p, AwsSecurityIdentity.reviewTitle(run), uri(p, run.sourceKey));
                if(review.isEmpty())review=gateway.reconcileCreate(p, AwsSecurityIdentity.legacyReviewTitle(run), uri(p, run.sourceKey));
                // Old uncertain creates used only the run UUID. Reconcile those without creating again.
                if(review.isEmpty())review=gateway.reconcileCreate(p, "watchtower-" + run.id, uri(p, run.sourceKey));
                var reconciled=review;
                change(run, owner, fence, r -> { r.needsReconciliation = reconciled.isEmpty(); r.dueAt = System.currentTimeMillis() + 60000;
                    reconciled.ifPresent(id -> { r.reviewId = id; r.stage = Stage.REVIEW_READY; }); });
            }
            case REVIEW_READY -> {
                if (stop) { change(run, owner, fence, r -> { r.stage = Stage.CANCELED; r.providerTerminal = true; r.terminalAt = System.currentTimeMillis(); }); return false; }
                // The review points at whichever scan set it up last: only start while this scan still holds the repository's lock.
                if (run.sharedReview && !repoReviews.holds(run.repositoryId, run.id, System.currentTimeMillis())) {
                    change(run, owner, fence, r -> r.stage = Stage.INPUT_READY); return false;
                }
                long attemptedAt = System.currentTimeMillis();
                change(run, owner, fence, r -> { r.stage = Stage.STARTING; r.startAttemptAt = attemptedAt; });
                String job;
                try { job = gateway.start(p, run.reviewId, run.diffKey == null ? null : uri(p, run.diffKey)); }
                catch (software.amazon.awssdk.services.securityagent.model.ValidationException rejected) {
                    rejected(run, owner, fence, "job start", rejected); return false;
                }
                if (job == null || job.isBlank()) throw new IOException("Job id unavailable");
                change(run, owner, fence, r -> { r.jobId = job; r.stage = Stage.RUNNING; });
            }
            case STARTING -> {
                if (run.sharedReview) { startingShared(run, owner, fence, p); return false; }
                var job = gateway.reconcileStart(p, run.reviewId);
                change(run, owner, fence, r -> { r.needsReconciliation = job.isEmpty(); r.dueAt = System.currentTimeMillis() + 60000;
                    job.ifPresent(id -> { r.jobId = id; r.stage = Stage.RUNNING; }); });
            }
            case RUNNING -> {
                // AWS may have completed while all pods were down. Read its result before
                // applying a local deadline or a switch changed during that outage.
                software.amazon.awssdk.services.securityagent.model.CodeReviewJob job;
                try { job = Objects.requireNonNull(gateway.job(p, run.reviewId, run.jobId)); }
                catch (RuntimeException unavailable) {
                    if (stop) requestProviderStop(run, owner, fence, p);
                    throw unavailable;
                }
                String status = job.statusAsString();
                boolean terminal = Set.of("COMPLETED", "FAILED", "STOPPED").contains(Objects.toString(status, ""));
                if (stop && !terminal) requestProviderStop(run, owner, fence, p);
                change(run, owner, fence, r -> {
                    r.jobReceiptJson = AwsSecurityJobReceipt.of(job).encode();
                    r.providerStatus = AwsSecurityFindingMapper.atom(status); r.needsReconciliation = false;
                    if (Set.of("COMPLETED", "FAILED", "STOPPED").contains(Objects.toString(status, ""))) {
                        r.providerTerminal = true; r.terminalAt = System.currentTimeMillis();
                        r.stage = Stage.IMPORTING; // Failed/stopped jobs may still contain useful returned evidence.
                    } else if (!Set.of("IN_PROGRESS", "STOPPING").contains(Objects.toString(status, ""))) r.needsReconciliation = true;
                });
            }
            case IMPORTING -> {
                var imported = importer.importAll(run, () -> change(run, owner, fence, r -> { }));
                change(run, owner, fence, r -> {
                    if (r.artifactKey != null) throw new IllegalStateException("Report already published");
                    r.nativeSeverityCounts.clear(); r.nativeSeverityCounts.putAll(imported.manifest().nativeSeverityCounts());
                    r.validationCounts.clear(); r.validationCounts.putAll(imported.manifest().validationCounts());
                    r.mapperVersion = AwsSecurityFindingMapper.VERSION;
                    r.artifactPages = imported.manifest().pages().size(); r.omittedCount = imported.manifest().omittedFindings();
                    r.artifactKey = imported.key(); r.importedCount = imported.manifest().imported(); r.missingCount = imported.manifest().missingIds().size();
                    r.stage = "FAILED".equals(r.providerStatus) ? Stage.FAILED : "STOPPED".equals(r.providerStatus) ? Stage.CANCELED
                        : "COMPLETE".equals(imported.manifest().importStatus()) ? Stage.COMPLETE : Stage.PARTIAL;
                    r.dueAt = 0; r.statusReason = "Provider evidence imported; prose omitted under source-free policy";
                });
            }
            default -> { }
        }
        return false;
    }
    /**
     * Gets this scan the repository's review pointed at its own source, under the repository lock: reuse the remembered review
     * (or adopt one found by its title, or create the first one), then update its source. Every call is safe to repeat, so an
     * uncertain one is simply retried from CREATING. True means the lock is held by another scan and the run waits.
     */
    private boolean sharedReview(AwsSecurityRun run, String owner, long fence, AwsSecuritySettings.Profile p) throws IOException {
        long now = System.currentTimeMillis();
        String title = AwsSecurityIdentity.repositoryReviewTitle(run), source = uri(p, run.sourceKey);
        var claim = repoReviews.acquire(run.repositoryId, p.spaceId(), title, run.id, now);
        if (!claim.held()) {
            change(run, owner, fence, r -> { r.dueAt = System.currentTimeMillis() + LOCK_WAIT_MS;
                r.statusReason = "Waiting for AWS: another scan of this repository is being set up"; });
            return true;
        }
        change(run, owner, fence, r -> { r.stage = Stage.CREATING; if (r.statusReason != null && r.statusReason.startsWith("Waiting for AWS: another scan")) r.statusReason = null; });
        String review = claim.reviewId();
        try {
            if (review != null) {
                try { gateway.updateSource(p, review, source); }
                catch (software.amazon.awssdk.services.securityagent.model.ResourceNotFoundException gone) {
                    repoReviews.forgetReview(run.repositoryId, run.id); review = null; // Deleted in AWS: make a new one below.
                }
            }
            if (review == null) {
                var existing = gateway.findReviewByTitle(p, title);
                if (existing.isPresent()) { review = existing.get(); gateway.updateSource(p, review, source); }
                else review = gateway.create(p, title, source);
                if (review == null || review.isBlank()) throw new IOException("Review id unavailable");
                repoReviews.recordReview(run.repositoryId, run.id, review);
            }
        } catch (software.amazon.awssdk.services.securityagent.model.ValidationException rejected) {
            rejected(run, owner, fence, "review update", rejected); return false;
        } catch (software.amazon.awssdk.awscore.exception.AwsServiceException denied) {
            if (!isAccessDenied(denied)) throw denied;
            // The runtime role may not have UpdateCodeReview yet: this scan keeps its own review, as scans did before sharing.
            LOG.warn("AWS refused to update the repository's shared review (access denied); scan {} uses its own review. Check that the runtime role has securityagent:UpdateCodeReview on the Agent Space and is allowed to pass the service role", run.id);
            repoReviews.release(run.repositoryId, run.id);
            change(run, owner, fence, r -> { r.sharedReview = false; r.stage = Stage.INPUT_READY; r.needsReconciliation = false; r.statusReason = null; r.dueAt = 0; });
            return false;
        }
        String ready = review;
        change(run, owner, fence, r -> { r.reviewId = ready; r.stage = Stage.REVIEW_READY; r.needsReconciliation = false; });
        return false;
    }
    private static boolean isAccessDenied(software.amazon.awssdk.awscore.exception.AwsServiceException e) {
        return e.statusCode() == 403 || (e.awsErrorDetails() != null && "AccessDeniedException".equals(e.awsErrorDetails().errorCode()));
    }
    /**
     * A start call that may or may not have reached AWS. The job it made records this scan's own source, which is unique to it,
     * so that job is the answer. Finding none is not proof until the list has had time to catch up; after that the scan goes back
     * to set up and start again under the lock.
     */
    private void startingShared(AwsSecurityRun run, String owner, long fence, AwsSecuritySettings.Profile p) {
        long now = System.currentTimeMillis();
        long attemptedAt = run.startAttemptAt == null ? now : run.startAttemptAt;
        var job = gateway.findJobBySource(p, run.reviewId, uri(p, run.sourceKey), java.time.Instant.ofEpochMilli(attemptedAt - CLOCK_SKEW_MS));
        if (job.isPresent()) {
            change(run, owner, fence, r -> { r.jobId = job.get(); r.stage = Stage.RUNNING; r.needsReconciliation = false; });
        } else if (now - attemptedAt < START_GRACE_MS) {
            change(run, owner, fence, r -> { r.needsReconciliation = true; r.dueAt = System.currentTimeMillis() + 30000; });
        } else {
            change(run, owner, fence, r -> { r.stage = Stage.INPUT_READY; r.needsReconciliation = false; r.startAttemptAt = null; r.dueAt = 0; });
        }
    }
    /** The lock is only needed until the job exists; once it is running (or the scan ended) the next scan of the repository may go. */
    private void releaseRepositoryLock(String id) {
        try {
            var run = runs.findById(id).orElse(null);
            if (run != null && run.sharedReview && (run.stage == Stage.RUNNING || run.finished())) repoReviews.release(run.repositoryId, run.id);
        } catch (RuntimeException keptUntilItExpires) { /* The lease expires on its own; never fail the run over it. */ }
    }
    /** A validation rejection proves this mutation was not accepted; a timeout does not. */
    private void rejected(AwsSecurityRun run, String owner, long fence, String operation,
            software.amazon.awssdk.services.securityagent.model.ValidationException failure) {
        // Retain only known schema field names. Provider messages may quote uploaded source or credentials.
        // AWS reports nested paths ("diffSource.s3Uri"), so a path is kept when its first segment is a known field and the
        // rest is plain schema-name characters.
        var fields = failure.fieldList().stream().map(f -> f.path()).filter(Objects::nonNull)
            .filter(path -> SCHEMA_PATH.matcher(path).matches() && SCHEMA_FIELDS.contains(path.split("[.\\[]", 2)[0]))
            .distinct().sorted().toList();
        boolean invalidTitle = "review creation".equals(operation) && Objects.toString(failure.getMessage(), "")
            .contains("Title can only contain letters, numbers, hyphens, and underscores.");
        change(run, owner, fence, r -> {
            r.stage = Stage.FAILED; r.providerTerminal = true; r.needsReconciliation = false;
            r.terminalAt = System.currentTimeMillis(); r.dueAt = 0; r.failureCount++;
            r.statusReason = "AWS rejected " + operation + " (ValidationException)" + (invalidTitle
                ? "; review titles allow letters, numbers, hyphens and underscores, up to 100 characters"
                : fields.isEmpty() ? "" : "; fields: " + String.join(", ", fields));
        });
    }
    private void requestProviderStop(AwsSecurityRun run, String owner, long fence, AwsSecuritySettings.Profile profile) {
        change(run, owner, fence, r -> r.stopRequested = true);
        try { gateway.stop(profile, run.jobId); }
        catch (RuntimeException denied) {
            change(run, owner, fence, r -> { r.statusReason = "Stop unavailable; continuing provider-terminal reconciliation"; r.failureCount++; if (throttled(denied)) r.throttleCount++; });
        }
    }
    private void prepare(AwsSecurityRun run, String owner, long fence) throws IOException {
        if("setup".equals(run.parentType)){prepareSetup(run,owner,fence);return;}
        var snapshot = AwsSecuritySnapshot.decode(run.snapshotJson); var c = snapshot.context(); var p = snapshot.profile();
        if (!settings.profile().revision().equals(p.revision())) throw new IOException("Profile readiness changed");
        gateway.readiness(p);
        var integration = integrations.findByLabel(c.apiLabel());
        if (integration == null || !(integration.createApi() instanceof IScmApi api)) throw new IOException("Source integration unavailable");
        Path directory = Files.createTempDirectory("aws-security-source-"); Path archive = Files.createTempFile("aws-security-", ".zip");
        Path diff = Files.createTempFile("aws-security-", ".diff");
        try {
            api.downloadSource(c.repository(), c.commit(), directory, new SourceDownloadLimits(AwsSecurityInputStore.MAX_ARCHIVE,
                AwsSecurityInputStore.MAX_EXPANDED, AwsSecurityInputStore.MAX_FILES));
            var zip = AwsSecurityInputStore.archive(directory, archive);
            if ("pull_request".equals(run.parentType)) {
                byte[] patch = api.rawDiff(c.repository(), c.commit(), c.mergeBase(), AwsSecurityInputStore.MAX_DIFF);
                AwsSecurityInputStore.validatePatch(patch);
                Files.write(diff, patch);
                String index = importer.writeDiffIndex(run.id, patch, () -> change(run, owner, fence, r -> { }));
                change(run, owner, fence, r -> r.diffIndexKey = index);
            }
            String prefix = AwsSecurityIdentity.inputPrefix(run);
            String diffSha = "pull_request".equals(run.parentType) ? AwsSecurityInputStore.sha256(diff) : null;
            long diffBytes = Files.size(diff);
            if (run.sourceSha != null && (!run.sourceSha.equals(zip.sha256()) || !Objects.equals(run.diffSha, diffSha)))
                throw new IOException("Pinned source checksum changed on resume");
            change(run, owner, fence, r -> { r.stage = Stage.PREPARING; r.sourceKey = prefix + "source.zip";
                r.sourceSha = zip.sha256(); r.sourceBytes = zip.bytes(); r.sourceFiles = zip.files();
                if (diffSha != null) { r.diffKey = prefix + DIFF_OBJECT; r.diffSha = diffSha; r.diffBytes = diffBytes; } });
            if (run.sourceIndexKey == null) {
                String sourceIndex = importer.writeSourceIndex(run.id, c.commit(), zip, () -> change(run, owner, fence, r -> { }));
                change(run, owner, fence, r -> r.sourceIndexKey = sourceIndex);
            }
            String sourceVersion = inputs.put(p, prefix + "source.zip", archive, zip.sha256());
            change(run, owner, fence, r -> r.sourceVersion = sourceVersion);
            String diffVersion = diffSha == null ? null : inputs.put(p, prefix + DIFF_OBJECT, diff, diffSha);
            // From here on a pull request or repository scan uses its repository's one shared review; setup tests keep their own.
            change(run, owner, fence, r -> { r.diffVersion = diffVersion; r.inputsVerified=true; r.sharedReview = true; r.stage = Stage.INPUT_READY; });
        } finally { FileUtils.deleteQuietly(directory.toFile()); Files.deleteIfExists(archive); Files.deleteIfExists(diff); }
    }
    private void prepareSetup(AwsSecurityRun run,String owner,long fence)throws IOException{
        var snapshot=AwsSecuritySnapshot.decode(run.snapshotJson);var p=snapshot.profile();
        if(run.setupMode==null||!settings.profile().revision().equals(p.revision())||settings.configurationIssue()!=null)
            throw new IOException("Synthetic setup profile changed");
        gateway.readiness(p);inputs.readiness(p);
        Path directory=Files.createTempDirectory("aws-synthetic-"),archive=Files.createTempFile("aws-synthetic-",".zip"),diff=Files.createTempFile("aws-synthetic-",".diff");
        try{
            AwsSecuritySetupFixture.write(directory,run.setupMode);
            var zip=AwsSecurityInputStore.archive(directory,archive);
            byte[] patch=run.setupMode==AwsSecuritySetupMode.DIFFERENTIAL?AwsSecuritySetupFixture.patch():null;
            String patchSha=null;
            if(patch!=null){AwsSecurityInputStore.validatePatch(patch);Files.write(diff,patch);patchSha=AwsSecurityInputStore.sha256(diff);}
            if(run.sourceSha!=null&&(!run.sourceSha.equals(zip.sha256())||!Objects.equals(run.diffSha,patchSha)))
                throw new IOException("Packaged synthetic fixture changed during recovery");
            String prefix=AwsSecurityIdentity.inputPrefix(run),diffSha=patchSha;
            change(run,owner,fence,r->{r.stage=Stage.PREPARING;r.sourceKey=prefix+"source.zip";r.sourceSha=zip.sha256();r.sourceBytes=zip.bytes();r.sourceFiles=zip.files();
                if(patch!=null){r.diffKey=prefix+DIFF_OBJECT;r.diffSha=diffSha;r.diffBytes=patch.length;}});
            if(run.sourceIndexKey==null){String index=importer.writeSourceIndex(run.id,snapshot.context().commit(),zip,()->change(run,owner,fence,r->{}));change(run,owner,fence,r->r.sourceIndexKey=index);}
            if(patch!=null&&run.diffIndexKey==null){String index=importer.writeDiffIndex(run.id,patch,()->change(run,owner,fence,r->{}));change(run,owner,fence,r->r.diffIndexKey=index);}
            String sourceVersion=inputs.put(p,prefix+"source.zip",archive,zip.sha256());
            change(run,owner,fence,r->r.sourceVersion=sourceVersion);
            String diffVersion=patch==null?null:inputs.put(p,prefix+DIFF_OBJECT,diff,patchSha);
            change(run,owner,fence,r->{r.diffVersion=diffVersion;r.inputsVerified=true;r.stage=Stage.INPUT_READY;});
        }finally{FileUtils.deleteQuietly(directory.toFile());Files.deleteIfExists(archive);Files.deleteIfExists(diff);}
    }
    private void cleanup(AwsSecurityRun run, String owner, long fence) {
        if(run.sourceKey==null&&run.diffKey==null&&!run.remotePossible()){
            change(run,owner,fence,r->{r.cleanupComplete=true;r.dueAt=Long.MAX_VALUE;});return;
        }
        var profile = AwsSecuritySnapshot.decode(run.snapshotJson).profile();
        if (!settings.profile().revision().equals(profile.revision()))
            throw new IllegalStateException("Restore frozen deployment profile before cleanup");
        if (run.remotePossible() && !run.providerTerminal) return;
        if (!run.cleanupComplete) {
            change(run, owner, fence, r -> r.cleanupAttempts++);
            inputs.delete(profile, run.sourceKey, run.sourceVersion); inputs.delete(profile, run.diffKey, run.diffVersion);
            change(run, owner, fence, r -> r.cleanupComplete = true);
        }
        // Review/job/finding records remain in AWS until an administrator explicitly deletes them.
        change(run, owner, fence, r -> r.dueAt = Long.MAX_VALUE);
    }
    private AwsSecurityRun change(AwsSecurityRun run, String owner, long fence, Consumer<AwsSecurityRun> operation) {
        return persistence.update(run.id, owner, fence, operation);
    }
    /** The reason shown for a failure before AWS was contacted: the size limits in words, else the stage and class. */
    static String sourcePreparationReason(Exception failure) {
        if (failure instanceof AwsSecurityInputStore.SourceLimitExceeded) {
            return "The source is over the AWS size limits (" + (AwsSecurityInputStore.MAX_FILE >> 20) + " MB per file, "
                + (AwsSecurityInputStore.MAX_EXPANDED >> 20) + " MB in all, " + AwsSecurityInputStore.MAX_FILES
                + " files); no AWS call was made";
        }
        return "Source preparation failed (" + failure.getClass().getSimpleName() + "); no AWS call was made";
    }
    static boolean throttled(Exception failure) {
        if (!(failure instanceof software.amazon.awssdk.awscore.exception.AwsServiceException aws)) return false;
        String code = aws.awsErrorDetails() == null ? "" : Objects.toString(aws.awsErrorDetails().errorCode(), "");
        return aws.statusCode() == 429 || code.toLowerCase(java.util.Locale.ROOT).contains("throttl") || code.contains("TooManyRequests");
    }
    static String uri(AwsSecuritySettings.Profile p, String key) { return "s3://" + p.bucket() + "/" + key; }
}
