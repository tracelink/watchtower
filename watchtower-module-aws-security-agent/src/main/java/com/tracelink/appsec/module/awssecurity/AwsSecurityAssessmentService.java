package com.tracelink.appsec.module.awssecurity;

import java.util.*;
import org.springframework.stereotype.Service;
import com.tracelink.appsec.watchtower.core.rule.*;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.module.ModuleControlService;
import com.tracelink.appsec.watchtower.core.scan.code.*;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;
import com.tracelink.appsec.watchtower.core.scan.presentation.FindingPresentationModel;
import com.tracelink.appsec.watchtower.core.feedback.FindingFeedbackService.Occurrence;

@Service
public class AwsSecurityAssessmentService implements RemoteAssessmentService {
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(AwsSecurityAssessmentService.class);
    private static final int MAX_LOGGED_CAUSE = 300;
    @org.springframework.beans.factory.annotation.Autowired private AwsSecurityEvidencePolicy evidencePolicy;
    private final AwsSecuritySettings settings;
    private final AwsSecurityRepositorySettingsRepository repositorySettings;
    private final RepositoryRepository repositories;
    private final AwsSecurityRunRepository runs;
    private final AwsSecurityPersistence persistence;
    private final AwsSecurityImporter importer;
    private final PRScanResultService prResults;
    private final ApiIntegrationService integrations;
    private final ModuleControlService controls;
    public AwsSecurityAssessmentService(AwsSecuritySettings settings, AwsSecurityRepositorySettingsRepository repositorySettings,
            RepositoryRepository repositories, AwsSecurityRunRepository runs,
            AwsSecurityPersistence persistence, AwsSecurityImporter importer,
            PRScanResultService prResults, ApiIntegrationService integrations, ModuleControlService controls) {
        this.settings=settings; this.repositorySettings=repositorySettings; this.repositories=repositories; this.runs=runs;
        this.persistence=persistence; this.importer=importer;
        this.prResults=prResults; this.integrations=integrations; this.controls=controls;
    }
    public boolean selected(RulesetDto rules) { return rules != null && rules.getAllRules().stream().anyMatch(AwsSecurityRuleDto.class::isInstance); }
    private AwsSecuritySnapshot snapshot(ScanExecutionContext context, RulesetDto rules) {
        var policies = rules.getAllRules().stream().filter(AwsSecurityRuleDto.class::isInstance).map(AwsSecurityRuleDto.class::cast).toList();
        if (policies.isEmpty()) throw new IllegalArgumentException("No AWS policy selected");
        if (policies.stream().map(AwsSecurityRuleDto::getRevision).distinct().count() != 1)
            throw new IllegalArgumentException("Conflicting AWS assessment policies");
        var policy = policies.getFirst();
        if (!"default".equals(policy.getProfile())) throw new IllegalArgumentException("Imported AWS policy requires explicit installation profile rebinding");
        return new AwsSecuritySnapshot(context, settings.profile(), policy.getExecutionIdentity(), policy.getName(), rules.getBlockingLevel(), policy.getRevision());
    }
    private String unavailable(long repositoryId) {
        String reason = settings.unavailable(); if (reason != null) return reason;
        if (!controls.enabled(AwsSecurityModule.NAME)) return "The AWS scanner is turned off. An administrator can turn it on under Scanner modules.";
        if (!importer.sharedArtifacts()) return "Shared S3 report storage is required for AWS assessment artifacts";
        return null;
    }
    /** A pull request's head and base as full commits, and their merge base. */
    record PinnedRefs(String head, String base, String mergeBase) { }
    /**
     * Bitbucket Cloud gives a pull request's commits as short hashes, which the pinned reads refuse (that is what
     * "merge-base unavailable" had been hiding), so each is completed before the merge base is asked for.
     */
    static PinnedRefs pin(IScmApi api, PullRequest pr) throws java.io.IOException {
        String head = api.fullCommit(pr.getRepoName(), pr.getCommitHash());
        String base = api.fullCommit(pr.getRepoName(), pr.getBaseCommitHash());
        return new PinnedRefs(head, base, api.mergeBase(pr.getRepoName(), head, base));
    }
    /** What was being looked up and why it failed, on one line: the integration, repository, pull request, short commits and the cause. */
    static String mergeBaseFailure(PullRequest pr, Exception cause) {
        return "AWS review not submitted for pull request #" + pr.getPrId() + " of '" + pr.getRepoName() + "' on integration '" + pr.getApiLabel()
                + "' (head " + shortCommit(pr.getCommitHash()) + ", base " + shortCommit(pr.getBaseCommitHash()) + "): "
                + cause.getClass().getSimpleName() + ": " + oneLine(cause.getMessage());
    }
    private static String shortCommit(String commit) { return commit == null ? "none" : commit.substring(0, Math.min(12, commit.length())); }
    /** One line, trimmed, so a long or multi-line cause cannot flood or split a log entry. */
    private static String oneLine(String text) {
        if (text == null) return "no message";
        String line = text.replaceAll("\\s+", " ").strip();
        return line.length() > MAX_LOGGED_CAUSE ? line.substring(0, MAX_LOGGED_CAUSE) + "…" : line;
    }
    public void preparePullRequest(PullRequest pr, RulesetDto rules, long startedAt) {
        var repo = repositories.findByApiLabelAndRepoName(pr.getApiLabel(), pr.getRepoName());
        long repoId = repo == null ? 0 : repo.getId(); String reason = unavailable(repoId); String mergeBase = null;
        String head = pr.getCommitHash(), base = pr.getBaseCommitHash();
        if (reason == null) {
            try {
                var integration = integrations.findByLabel(pr.getApiLabel());
                if (integration == null) throw new IllegalStateException("no integration is labelled '" + pr.getApiLabel() + "'");
                if (!(integration.createApi() instanceof IScmApi api)) throw new IllegalStateException("integration '" + pr.getApiLabel() + "' is not a source control integration");
                var pinned = pin(api, pr);
                head = pinned.head(); base = pinned.base(); mergeBase = pinned.mergeBase();
            } catch (Exception e) {
                reason = "Pinned PR base/merge-base unavailable; no AWS submission";
                // The reason shown to people stays short; the real cause is here for whoever has to fix it.
                LOG.warn("{}", mergeBaseFailure(pr, e));
                LOG.debug("Merge base lookup failed", e);
            }
        }
        String execution = RuleRevision.definition("aws-pr-parent", "v1").field("api", pr.getApiLabel()).field("repo", pr.getRepoName())
            .field("pr", pr.getPrId()).field("head", pr.getCommitHash()).field("base", pr.getBaseCommitHash())
            .field("submitted", Long.toString(pr.getSubmitTime())).hash();
        var context = new ScanExecutionContext(execution, CodeScanType.PULL_REQUEST, 0, repoId, pr.getApiLabel(), pr.getRepoName(),
            pr.getSourceBranch(), head, pr.getPrId(), pr.getDestinationBranch(), base, mergeBase);
        var run = persistence.enlist(snapshot(context, rules), settings.reviewSeconds(), reason, () -> prResults.reserveRemoteParent(pr, startedAt));
        pr.setExecutionScanId(run.parentId);
    }
    public String prepareRepository(ScanExecutionContext context, RulesetDto rules) {
        var previous = runs.findByParentTypeAndParentIdOrderByCreatedAtAsc("repository", context.scanId());
        if (!previous.isEmpty()) return previous.getFirst().id;
        return persistence.enlist(snapshot(context, rules), settings.reviewSeconds(), unavailable(context.repositoryId())).id;
    }
    public Optional<ScanExecutionContext> repositoryContext(long scanId) {
        return runs.findByParentTypeAndParentIdOrderByCreatedAtAsc("repository", scanId).stream().findFirst()
            .map(r -> AwsSecuritySnapshot.decode(r.snapshotJson).context());
    }
    public Optional<RepositoryAdmissionBlocker> repositoryAdmissionBlocker() {
        return Optional.empty();
    }
    public void cancelRepository(String runId) { persistence.requestStop(runId); }
    public List<com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference> reports(String type, long scanId) {
        return runs.findByParentTypeAndParentIdOrderByCreatedAtAsc(type, scanId).stream().map(r -> {
            var reference = r.reference();
            if (r.artifactKey == null) return reference;
            try {
                var manifest = importer.manifest(r.artifactKey); var c = reference.context();
                var status = new Status(r.id, reference.status().state(), r.statusReason, c.commit(), c.baseCommit(), r.reviewId, r.jobId,
                    r.importedCount, r.missingCount, r.cleanupComplete, r.stage == AwsSecurityRun.Stage.COMPLETE && "COMPLETE".equals(manifest.importStatus()),
                    manifest.providerFindingCap(), manifest.pages().size(), manifest.nativeSeverityCounts(), reference.status().receiptFacts(), reference.status().progress());
                return new com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference(reference.provider(), r.id, r.artifactKey, status,
                    c, reference.policy(), reference.policyName(), reference.policyRevision(), manifest.validationCounts(), manifest.omittedFindings());
            } catch (java.io.IOException unavailable) {
                var old = reference.status();
                var status = new Status(old.id(), old.state(), "Retained provider evidence unavailable", old.commit(), old.baseCommit(), old.reviewId(), old.jobId(), old.imported(), old.missing(), old.cleanupComplete(), false, old.providerCap(), old.pages(), old.nativeSeverityCounts(), old.receiptFacts(), old.progress());
                return new com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference(reference.provider(), r.id, r.artifactKey, status,
                    reference.context(), reference.policy(), reference.policyName(), reference.policyRevision(), reference.validationCounts(), reference.omittedFindings());
            }
        }).toList();
    }
    public Object receipt(com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference reference) throws java.io.IOException {
        var receipt = new java.util.LinkedHashMap<String, Object>(); receipt.put("assessment", reference);
        if (reference.artifactKey() != null) receipt.put("manifest", importer.manifest(reference.artifactKey()));
        return receipt;
    }
    public List<ProviderOccurrence> evidence(com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference reference, int page) throws java.io.IOException {
        if (reference.artifactKey() == null) return List.of();
        var manifest = importer.manifest(reference.artifactKey());
        if (!manifest.runId().equals(reference.runId()) || !manifest.snapshot().context().equals(reference.context())) throw new java.io.IOException("Provider report association mismatch");
        return importer.page(manifest, page).stream().map(o -> new ProviderOccurrence(o.key(), o.details(), o.changedLineAnchors())).toList();
    }
    public List<Status> status(String type, long scanId) {
        return reports(type,scanId).stream().map(reference->{
            var status=reference.status();
            String url=status.providerDeleted()||evidencePolicy==null?null:AwsSecurityEvidencePolicy.reviewUrl(evidencePolicy.webAppUrl(),status.receiptFacts().get("Agent Space"),status.reviewId());
            return url==null?status:status.withProviderUrl(url);
        }).toList();
    }
    public List<FindingPresentationModel> findings(String type, long scanId, int page) {
        List<FindingPresentationModel> results = new ArrayList<>();
        for (var r : runs.findByParentTypeAndParentIdOrderByCreatedAtAsc(type, scanId)) {
            if (r.artifactKey == null) continue;
            try {
                var manifest = importer.manifest(r.artifactKey);
                if (page < 0 || page >= manifest.pages().size()) continue;
                String base = ("repository".equals(type) ? "/reposcan/report/" : "/scan/report/") + scanId;
                for (var finding : importer.page(manifest, page)) results.add(FindingPresentationModel.fromProvider(finding.key(), finding.details())
                    .withProviderDetailUrl(base + "/aws/findings/" + finding.key() + "?page=" + page));
            } catch (java.io.IOException e) { throw new IllegalStateException("AWS report page unavailable"); }
        }
        return results;
    }
    public Optional<Occurrence> occurrence(String type, long scanId, String key) {
        for (var r : runs.findByParentTypeAndParentIdOrderByCreatedAtAsc(type, scanId)) {
            if (r.artifactKey == null) continue;
            try {
                var manifest = importer.manifest(r.artifactKey);
                for (int page = 0; page < manifest.pages().size(); page++) {
                    for (var f : importer.page(manifest, page)) if (key.equals(f.key())) {
                        var rule = manifest.snapshot().rule();
                        return Optional.of(new Occurrence(rule.ruleId(), rule.revision(), null, r.terminalAt));
                    }
                }
            } catch (java.io.IOException e) { throw new IllegalStateException("AWS finding unavailable"); }
        }
        return Optional.empty();
    }
    public Set<com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.BypassedFinding> bypassFindings(long scanId) {
        var covered = new HashSet<com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.BypassedFinding>();
        for (var run : runs.findByParentTypeAndParentIdOrderByCreatedAtAsc("pull_request", scanId)) {
            if (run.artifactKey == null) continue;
            try {
                var manifest = importer.manifest(run.artifactKey);
                for (int page=0; page<manifest.pages().size(); page++) for (var finding : importer.page(manifest, page))
                    for (var anchor : finding.changedLineAnchors()) covered.add(new com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.BypassedFinding(manifest.snapshot().ruleName(), anchor.file()));
            } catch (java.io.IOException e) { throw new IllegalStateException("Provider bypass evidence unavailable"); }
        }
        return Set.copyOf(covered);
    }
}
