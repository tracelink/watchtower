package com.tracelink.appsec.module.awssecurity;

import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.data.domain.PageRequest;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import com.tracelink.appsec.watchtower.core.module.ModuleControlService;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;
import com.tracelink.appsec.watchtower.core.scan.code.CommitIds;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestState;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRStatusComment;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRProviderInlineComments;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.ActiveBypass;
import com.tracelink.appsec.watchtower.core.scan.presentation.ProviderFindingTitles;
import com.tracelink.appsec.watchtower.core.scan.code.report.ProviderFindingDetails;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PRScanBypassService;
import com.tracelink.appsec.module.awssecurity.AwsPrDecision.*;

/** Dormant until failure policy AND live enforcement are explicitly configured after Dev gates. */
@Service
public class AwsPrPublisher {
    private final AwsSecuritySettings settings;
    private final boolean enabled;
    private final FailurePolicy failurePolicy;
    private final AwsSecurityRunRepository runs;
    private final AwsSecurityPersistence persistence;
    private final AwsSecurityImporter importer;
    private final PRScanRepository scans;
    private final PRScanBypassService bypasses;
    private final ApiIntegrationService integrations;
    private final RepositoryRepository repositories;
    private final ModuleControlService controls;
    private final TransactionTemplate transactions;
    /** Optional (absent in module tests): counts a pull request scan in the dashboard figures once it finishes. */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private com.tracelink.appsec.watchtower.core.metrics.MetricsProjectionWriter metrics;
    /** Optional (absent in module tests): the policy chosen on the settings page; without it the deployment value passed in applies. */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private AwsSecurityFailurePolicyStore failurePolicies;
    /** Optional (absent in module tests): the PR settings that switch the status comment, and the public URL its link needs. */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PullRequestSyncSettingsService prSettings;
    @Value("${watchtower.publicUrl:}") private String publicUrl;
    private FailurePolicy policy() { return failurePolicies != null ? failurePolicies.current() : failurePolicy; }
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(AwsPrPublisher.class);
    /** The last reason each run could not be published, so the 30-second schedule logs a reason once, not for ever. */
    private final java.util.Map<String, String> lastSkip = new java.util.concurrent.ConcurrentHashMap<>();
    public AwsPrPublisher(AwsSecuritySettings settings, @Value("${watchtower.aws-security.pr-enforcement:false}") boolean enabled,
            @Value("${watchtower.aws-security.failure-policy:UNDECIDED}") FailurePolicy failurePolicy,
            AwsSecurityRunRepository runs, AwsSecurityPersistence persistence, AwsSecurityImporter importer,
            PRScanRepository scans, PRScanBypassService bypasses, ApiIntegrationService integrations,
            RepositoryRepository repositories, ModuleControlService controls, PlatformTransactionManager transactions) {
        this.settings=settings; this.enabled=enabled; this.failurePolicy=failurePolicy; this.runs=runs; this.persistence=persistence;
        this.importer=importer; this.scans=scans; this.bypasses=bypasses; this.integrations=integrations;
        this.repositories=repositories; this.controls=controls; this.transactions=new TransactionTemplate(transactions);
    }
    @Scheduled(fixedDelayString = "${watchtower.aws-security.publish-ms:30000}")
    public void publishReady() {
        // An undecided failure policy still lets a failed or inconclusive review close its scan; publish() never touches the pull request then.
        if (!enabled || settings.unavailable() != null || !controls.enabled(AwsSecurityModule.NAME)) return;
        for (var candidate : runs.findByParentTypeAndAggregatePublishedFalseOrderByCreatedAtAsc("pull_request", PageRequest.of(0,100))) {
            if (!candidate.finished() || candidate.scmAttempted) continue;
            String owner = UUID.randomUUID().toString();
            var claimed = persistence.claim(candidate.id, owner, System.currentTimeMillis()); if (claimed.isEmpty()) continue;
            var run = claimed.get();
            try { publish(run, owner); }
            catch (Exception e) {
                // An attempted SCM mutation stays unresolved; never infer acceptance or retry a comment blindly. Only the class is logged:
                // provider messages may quote source.
                skip(run, "failed with " + e.getClass().getSimpleName());
            }
            finally { persistence.release(run.id, owner, run.fence); }
        }
    }
    void publish(AwsSecurityRun run, String owner) throws Exception {
        var scan = scans.findById(Long.valueOf(run.parentId)).orElse(null);
        if (scan == null || !scan.isPerformanceComplete()) { skip(run, scan == null ? "its pull request scan no longer exists" : "its local scan is not marked complete"); return; }
        var snapshot = AwsSecuritySnapshot.decode(run.snapshotJson); var c = snapshot.context();
        var blocker = policyBlocker(run, snapshot);
        if (blocker != null) { skip(run, blocker); return; }
        var integration = integrations.findByLabel(c.apiLabel());
        if (integration == null || !(integration.createApi() instanceof IScmApi api)) { skip(run, "its source control integration is unavailable"); return; }
        PullRequest reference = scan.getContainer().toPullRequest();
        var current = api.updatePRData(reference);
        if (!fresh(c, current)) { mark(run, owner, "SUPERSEDED", false, false); statusComment(api, current, scan, null, null, PRStatusComment.Result.SUPERSEDED); return; }
        var bypass = bypasses.activeFor(c.apiLabel(), c.repository(), c.pullRequestId()).orElse(null);
        boolean localBlocks = scan.getViolations().stream().anyMatch(v -> v.isNewViolation() && Boolean.TRUE.equals(v.getEffectiveBlocking())
            && (bypass == null || !bypass.covers(v.getViolationName(), v.getFileName())));
        var policy = policy();
        int findingCount = 0; int returnedFindings = -1; java.util.Map<String, Integer> severities = java.util.Map.of();
        var inlineFindings = new ArrayList<PRProviderInlineComments.Finding>();
        var rows = new ArrayList<PRStatusComment.Row>();
        var decision = AwsPrDecision.decide(snapshot, List.of(), run.stage == AwsSecurityRun.Stage.COMPLETE && run.artifactKey != null, localBlocks, bypass, policy);
        if (run.artifactKey != null) {
            var manifest = importer.manifest(run.artifactKey); returnedFindings = manifest.returned(); severities = manifest.nativeSeverityCounts();
            if (!"COMPLETE".equals(manifest.importStatus()) && decision != Decision.BLOCK) decision = Decision.INCOMPLETE;
            for (int page = 0; page < manifest.pages().size(); page++) {
                var findings = importer.page(manifest, page); findingCount += findings.size(); collectInline(findings, snapshot, bypass, inlineFindings); collectRows(findings, snapshot, bypass, rows);
                var pageDecision = AwsPrDecision.decide(snapshot, findings, true, false, bypass, policy);
                if (pageDecision == Decision.BLOCK) decision = Decision.BLOCK;
                else if (pageDecision == Decision.INCOMPLETE && decision != Decision.BLOCK) decision = Decision.INCOMPLETE;
            }
            if (findingCount != manifest.imported() && decision != Decision.BLOCK) decision = Decision.INCOMPLETE;
        }
        // AWS could not finish: the job failed or was stopped, or the review failed, was cancelled or never started. Findings that came
        // back, a partial import or a finding without a changed line are not failures and stay incomplete.
        // A job AWS finished but Watchtower could not import may hold findings nobody has seen, so that is never passed.
        boolean importFailed = run.importAttempts > 0 || "COMPLETED".equals(Objects.toString(run.providerStatus, ""));
        boolean terminalError = run.providerTerminal && Set.of("FAILED", "STOPPED").contains(Objects.toString(run.providerStatus, ""))
            || !importFailed && Set.of(AwsSecurityRun.Stage.FAILED, AwsSecurityRun.Stage.CANCELED, AwsSecurityRun.Stage.UNAVAILABLE).contains(run.stage);
        boolean noEvidence = findingCount == 0 && run.missingCount == 0 && (run.artifactKey == null || returnedFindings == 0);
        if (decision == Decision.INCOMPLETE && terminalError && noEvidence && policy == FailurePolicy.PASS_ON_ERROR)
            decision = localBlocks ? Decision.BLOCK : Decision.ALLOW;
        if (decision == Decision.INCOMPLETE) { mark(run, owner, "INCOMPLETE", false, false); statusComment(api, current, scan, null, null, PRStatusComment.Result.INCOMPLETE); return; }
        // Approving or blocking is a policy decision: until the failure policy is chosen nothing is changed on the pull request.
        if (policy == FailurePolicy.UNDECIDED) return;
        // Every mutation gets a fresh head/base, permission, policy, bypass and fencing check.
        if (!readyForMutation(run, owner, snapshot, api, reference, bypass)) return;
        persistence.update(run.id, owner, run.fence, r -> r.scmAttempted = true);
        commentFindings(api, current, inlineFindings);
        boolean block = decision == Decision.BLOCK;
        boolean accepted;
        if (block) {
            accepted = api.requestChangesPR(current);
            if (!accepted || !readyForMutation(run, owner, snapshot, api, reference, bypass)) return;
            accepted = api.blockPR(current);
        } else accepted = api.approvePR(current);
        if (!accepted) return;
        if (!readyForMutation(run, owner, snapshot, api, reference, bypass)) return;
        boolean commented;
        if (statusCommentsEnabled()) {
            // The pull request's one comment becomes the scan summary, with the AWS result as one line.
            var remote = terminalError ? null : new PRStatusComment.Remote(findingCount, severities,
                (int) inlineFindings.stream().filter(f -> f.blocking() && !f.bypassed()).count(), topRows(rows));
            commented = statusComment(api, current, scan, terminalError ? null : severities, terminalError ? null : (Integer) findingCount,
                block ? PRStatusComment.Result.BLOCKED : terminalError ? PRStatusComment.Result.PASSED_BY_POLICY : PRStatusComment.Result.PASSED,
                remote, bypass, inlineFindings.stream().anyMatch(PRProviderInlineComments.Finding::bypassed));
        } else {
            commented = api.sendComment(current, "Watchtower security assessment: " + (block ? "blocking findings" : terminalError ? "provider error passed by configured policy" : "completed within the selected threshold")
                + ". AWS findings: " + run.importedCount + ". Commit: " + c.commit() + ". Confidence does not establish exploitation.");
        }
        if (commented) mark(run, owner, terminalError ? "ERROR_PASSED" : "COMPLETE", block, true);
    }
    /** The findings AWS returned that sit on changed lines, as inline comments: severity, plain title and a link, never source or provider prose. */
    private static void collectInline(List<AwsSecurityArtifact.Occurrence> findings, AwsSecuritySnapshot snapshot, ActiveBypass bypass,
            List<PRProviderInlineComments.Finding> into) {
        for (var occurrence : findings) {
            var details = occurrence.details();
            String title = titleWithReason(details, snapshot);
            boolean blocking = blocks(details, snapshot);
            for (var anchor : occurrence.changedLineAnchors()) {
                boolean bypassed = blocking && bypass != null && bypass.covers(snapshot.ruleName(), anchor.file());
                into.add(new PRProviderInlineComments.Finding(anchor.file(), anchor.startLine(), details.severity(), title, blocking, bypassed));
            }
        }
    }
    /** The plain title a comment shows; only a finding about a secret or credential gets the generic one, never one that merely has no source to show. */
    private static String commentTitle(ProviderFindingDetails details) {
        return AwsSecurityFindingMapper.SECRET_REASON.equals(details.sensitivityReason()) ? "Possible secret or credential"
            : ProviderFindingTitles.plain(details.title(), details.riskType());
    }
    /** The plain title, plus why a finding of a blocking severity does not block when AWS is not highly confident about it. */
    private static String titleWithReason(ProviderFindingDetails details, AwsSecuritySnapshot snapshot) {
        String note = AwsPrDecision.notBlockingNote(details, snapshot);
        return note == null ? commentTitle(details) : commentTitle(details) + " (" + note + ")";
    }
    private static boolean blocks(ProviderFindingDetails details, AwsSecuritySnapshot snapshot) {
        var priority = details.legacyPriority();
        return AwsPrDecision.confident(details) && priority != null && snapshot.blockingLevel() != null && priority.compareTo(snapshot.blockingLevel()) <= 0;
    }
    /** One row per finding for the summary comment, with its changed line when it has one. */
    private static void collectRows(List<AwsSecurityArtifact.Occurrence> findings, AwsSecuritySnapshot snapshot, ActiveBypass bypass,
            List<PRStatusComment.Row> into) {
        for (var occurrence : findings) {
            var details = occurrence.details();
            var where = !occurrence.changedLineAnchors().isEmpty() ? occurrence.changedLineAnchors().getFirst()
                : details.locations().isEmpty() ? null : details.locations().getFirst();
            boolean blocking = blocks(details, snapshot) && !occurrence.changedLineAnchors().isEmpty();
            boolean bypassed = blocking && bypass != null && occurrence.changedLineAnchors().stream().allMatch(l -> bypass.covers(snapshot.ruleName(), l.file()));
            into.add(new PRStatusComment.Row(severityName(details.severity()), titleWithReason(details, snapshot), where == null ? null : where.file(),
                where == null ? 0 : where.startLine(), blocking, bypassed));
        }
    }
    private static final List<String> SEVERITY_ORDER = List.of("Critical", "High", "Medium", "Low", "Informational");
    private static String severityName(String severity) {
        if (severity == null || severity.isBlank()) return "Unknown";
        return severity.substring(0, 1).toUpperCase(java.util.Locale.ROOT) + severity.substring(1).toLowerCase(java.util.Locale.ROOT);
    }
    /** Blocking first, then worst severity, then file and line: the findings a developer should read first. */
    private static List<PRStatusComment.Row> topRows(List<PRStatusComment.Row> rows) {
        return rows.stream().sorted(java.util.Comparator.comparing((PRStatusComment.Row r) -> !r.blocking() || r.bypassed())
            .thenComparingInt(r -> { int i = SEVERITY_ORDER.indexOf(r.priority()); return i < 0 ? SEVERITY_ORDER.size() : i; })
            .thenComparing(PRStatusComment.Row::file, java.util.Comparator.nullsLast(java.util.Comparator.naturalOrder()))
            .thenComparingInt(PRStatusComment.Row::line)).limit(PRStatusComment.Remote.MAX_ROWS).toList();
    }
    /** Best effort and idempotent: a failure here never stops the review state from being set. */
    private void commentFindings(IScmApi api, PullRequest pr, List<PRProviderInlineComments.Finding> findings) {
        try {
            if (findings.isEmpty() || !statusCommentsEnabled()) return;
            PRProviderInlineComments.sync(api, pr, findings, pr.getCommitHash(), PRStatusComment.reportLink(publicUrl, pr));
        } catch (RuntimeException failure) { LOG.warn("Could not comment AWS findings on {}", pr.getPRString(), failure); }
    }
    /** The comments Watchtower puts on a pull request for its scans are one setting: the PR settings page's "Scan status comment". */
    private boolean statusCommentsEnabled() {
        return prSettings != null && prSettings.getSettings() != null && prSettings.getSettings().isStatusCommentsEnabled();
    }
    /** The pull request's one status comment, finished off with what AWS found and the result. Best effort: it never affects the scan. */
    private boolean statusComment(IScmApi api, PullRequest pr, PullRequestScanEntity scan, java.util.Map<String, Integer> severities,
            Integer remoteFindings, PRStatusComment.Result result) {
        return statusComment(api, pr, scan, severities, remoteFindings, result, null, null, false);
    }
    private boolean statusComment(IScmApi api, PullRequest pr, PullRequestScanEntity scan, java.util.Map<String, Integer> severities,
            Integer remoteFindings, PRStatusComment.Result result, PRStatusComment.Remote remote, ActiveBypass bypass, boolean remoteBypassed) {
        try {
            if (!statusCommentsEnabled()) return true;
            var reported = scan.getViolations().stream().filter(v -> v.getViolationName() == null || !v.getViolationName().startsWith("MCR Match:")).toList();
            boolean bypassApplied = bypass != null && (remoteBypassed || reported.stream().anyMatch(v -> v.isBypassed()));
            String link = PRStatusComment.reportLink(publicUrl, pr);
            // Without an AWS result there is still a summary when local scanners found something: it lists those findings and names
            // AWS as the scanner that did not finish, so a pull request blocked by a local finding says why.
            // The scan stopped at "local scanners done" while this review ran, so the local findings' inline comments are posted here.
            int notInline = reported.isEmpty() ? 0 : PRProviderInlineComments.syncLocalFindings(api, pr, reported, bypassApplied ? bypass : null, pr.getCommitHash());
            String summary = remote == null && reported.isEmpty() ? null : PRStatusComment.finalSummary(reported,
                remote == null ? List.of("AWS Security Agent") : List.of(), bypassApplied ? bypass : null, notInline,
                pr.getCommitHash(), link, false, remote);
            return PRStatusComment.post(api, pr, new PRStatusComment.Status(pr.getCommitHash(), PRStatusComment.Phase.FINISHED, true, reported.size(),
                remoteFindings, severities, result, link, summary));
        } catch (RuntimeException failure) { LOG.warn("Could not update the status comment for run {}", pr.getPRString(), failure); return false; }
    }
    private boolean policyCurrent(AwsSecurityRun run, AwsSecuritySnapshot snapshot) { return policyBlocker(run, snapshot) == null; }
    /** Why the policy this run was started under no longer holds, or null when it still does. */
    private String policyBlocker(AwsSecurityRun run, AwsSecuritySnapshot snapshot) {
        // Whether a repository is reviewed is decided by its ruleset (see the operations guide); the old per-repository permission rows are not consulted.
        if (settings.unavailable() != null || !controls.enabled(AwsSecurityModule.NAME)) return "the AWS module or its settings are unavailable";
        if (!settings.profile().revision().equals(snapshot.profile().revision())) return "the AWS connection settings changed since the scan";
        var repo = repositories.findById(run.repositoryId).orElse(null);
        if (repo == null || repo.getRuleset() == null) return "the repository or its ruleset is gone";
        var rules = repo.getRuleset().toDto();
        var policies = rules.getAllRules().stream().filter(AwsSecurityRuleDto.class::isInstance).toList();
        if (policies.isEmpty()) return "the ruleset no longer has the AWS security review";
        if (!Objects.equals(rules.getBlockingLevel(), snapshot.blockingLevel())) return "the ruleset's blocking level changed since the scan";
        if (!policies.stream().allMatch(r -> r.getRevision().equals(snapshot.policyRevision()))) return "the AWS policy was edited since the scan";
        return null;
    }
    private void skip(AwsSecurityRun run, String reason) {
        if (!reason.equals(lastSkip.put(run.id, reason))) LOG.info("AWS pull request review {} is not published: {}", run.id, reason);
    }
    private boolean readyForMutation(AwsSecurityRun run, String owner, AwsSecuritySnapshot snapshot, IScmApi api,
            PullRequest reference, com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.ActiveBypass bypass) throws Exception {
        var c = snapshot.context();
        var latest = bypasses.activeFor(c.apiLabel(), c.repository(), c.pullRequestId()).orElse(null);
        // Entity equality is not used: compare the complete effective bypass value.
        if (!Objects.equals(bypass, latest) || !policyCurrent(run, snapshot)
                || !fresh(c, api.updatePRData(reference))) return false;
        persistence.update(run.id, owner, run.fence, r -> { });
        return true;
    }
    static boolean fresh(com.tracelink.appsec.watchtower.core.scan.code.ScanExecutionContext c, PullRequest pr) {
        // Bitbucket reports 12-character commits; the review pinned the full ones.
        return pr.getState() == PullRequestState.ACTIVE && CommitIds.same(c.commit(), pr.getCommitHash())
            && CommitIds.same(c.baseCommit(), pr.getBaseCommitHash())
            && Objects.equals(c.targetBranch(), pr.getDestinationBranch());
    }
    private void mark(AwsSecurityRun run, String owner, String state, boolean blocked, boolean completed) {
        transactions.executeWithoutResult(tx -> {
            // The run's own reason (why AWS failed, what it rejected) is what a person needs; the aggregate state is only a fallback.
            persistence.update(run.id, owner, run.fence, r -> { r.aggregatePublished = true; if (r.statusReason == null || r.statusReason.isBlank()) r.statusReason = "PR aggregate: " + state; });
            var scan = scans.findById(Long.valueOf(run.parentId)).orElseThrow();
            scan.setRemoteAssessmentState(state); scan.setRemoteCompletedAt(System.currentTimeMillis()); scan.setBlocked(blocked);
            // A review that completed on a pull request that has since moved on did not fail: the scan finished, it just is not published.
            boolean finishedReview = completed && "COMPLETE".equals(state) || "SUPERSEDED".equals(state) && run.stage == AwsSecurityRun.Stage.COMPLETE;
            scan.setStatus(finishedReview ? ScanStatus.DONE : ScanStatus.FAILED); scans.saveAndFlush(scan);
        });
        recordFinishedScan(run);
    }
    /**
     * A pull request scan that waits for AWS is saved as in progress, and the dashboard counts a scan only once it is done, so
     * this is the first moment it can be counted: its scan, its stage timings and the time AWS kept it open. Each is recorded once
     * by its own marker, and a failure here never undoes the scan's result.
     */
    private void recordFinishedScan(AwsSecurityRun run) {
        if (metrics == null) return;
        try {
            transactions.executeWithoutResult(tx -> scans.findById(Long.valueOf(run.parentId)).ifPresent(scan -> {
                if (scan.getStatus() != ScanStatus.DONE) return;
                metrics.record("pull_request", scan, scan.getViolations());
                metrics.recordPrPerformance(scan);
                if (run.terminalAt > 0) metrics.recordProviderWait(scan.getId(), scan.getEndDateMillis(), run.terminalAt - scan.getEndDateMillis(), scan.isPerformanceComplete());
            }));
        } catch (RuntimeException failure) { metrics.recordFailure("pull_request", failure); }
    }
}
