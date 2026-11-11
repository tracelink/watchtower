package com.tracelink.appsec.module.awssecurity;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import java.util.*;
import org.junit.jupiter.api.*;
import com.tracelink.appsec.watchtower.core.module.ModuleControlService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.*;
import com.tracelink.appsec.watchtower.core.scan.repository.*;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.*;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.*;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.PRScanBypassService;
import com.tracelink.appsec.watchtower.core.ruleset.*;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

class AwsPrPublisherTest {
    AwsPrPublisher publisher; AwsSecurityRun run; AwsSecurityPersistence persistence; IScmApi api;
    RulesetDto rules; PullRequest current; PullRequestScanEntity scan;
    @BeforeEach void setup() throws Exception {
        run=AwsTestSupport.run();run.artifactKey="manifest";run.stage=AwsSecurityRun.Stage.COMPLETE;run.owner="owner";
        var snapshot=AwsSecuritySnapshot.decode(run.snapshotJson);
        var scans=mock(PRScanRepository.class);scan=mock(PullRequestScanEntity.class);when(scans.findById(Long.valueOf(1))).thenReturn(Optional.of(scan));
        when(scan.isPerformanceComplete()).thenReturn(true);when(scan.getViolations()).thenReturn(List.of());
        var container=mock(PullRequestContainerEntity.class);when(scan.getContainer()).thenReturn(container);
        current=new PullRequest("bb");current.setState(PullRequestState.ACTIVE);current.setCommitHash(snapshot.context().commit());
        current.setBaseCommitHash(snapshot.context().baseCommit());current.setDestinationBranch("main");when(container.toPullRequest()).thenReturn(current);
        api=mock(IScmApi.class);when(api.updatePRData(any())).thenAnswer(i->current);when(api.approvePR(any())).thenReturn(true);
        var integrations=mock(ApiIntegrationService.class);var integration=mock(ApiIntegrationEntity.class);
        when(integrations.findByLabel("bb")).thenReturn(integration);when(integration.createApi()).thenReturn(api);
        var repositories=mock(RepositoryRepository.class);var repository=mock(RepositoryEntity.class);
        when(repositories.findById(2L)).thenReturn(Optional.of(repository));var ruleset=mock(RulesetEntity.class);when(repository.getRuleset()).thenReturn(ruleset);
        var policy=new AwsSecurityRuleDto();policy.setId(7L);policy.setName("AWS policy");policy.setPriority(RulePriority.HIGH);
        rules=new RulesetDto();rules.setName("test");rules.setRules(Set.of(policy));rules.setBlockingLevel(RulePriority.HIGH);when(ruleset.toDto()).thenReturn(rules);
        var controls=mock(ModuleControlService.class);when(controls.enabled(AwsSecurityModule.NAME)).thenReturn(true);
        persistence=mock(AwsSecurityPersistence.class);
        var importer=mock(AwsSecurityImporter.class);
        when(importer.manifest("manifest")).thenReturn(new AwsSecurityArtifact(1,run.id,snapshot,"COMPLETED","COMPLETE",1,0,0,List.of(),List.of(),30,List.of(),null,Map.of(),Map.of()));
        publisher=new AwsPrPublisher(AwsTestSupport.settings(),true,AwsPrDecision.FailurePolicy.KEEP_INCOMPLETE,
            mock(AwsSecurityRunRepository.class),persistence,importer,scans,mock(PRScanBypassService.class),
            integrations,repositories,controls,mock(org.springframework.transaction.PlatformTransactionManager.class));
    }
    @Test void aRulesetWithoutTheAwsReviewNeverPublishes() throws Exception {
        rules.setRules(Set.of());publisher.publish(run,"owner");verify(api,never()).approvePR(any());verify(api,never()).sendComment(any(),any());
    }
    @Test void changedHeadAfterApprovalSuppressesComment() throws Exception {
        when(api.approvePR(any())).thenAnswer(i->{current.setCommitHash("d".repeat(40));return true;});
        publisher.publish(run,"owner");verify(api).approvePR(any());verify(api,never()).sendComment(any(),any());
    }
    @Test void theRulesetIsRecheckedBetweenRequestChangesAndBlock() throws Exception {
        var violation=mock(PullRequestViolationEntity.class);when(violation.isNewViolation()).thenReturn(true);when(violation.getEffectiveBlocking()).thenReturn(true);
        when(scan.getViolations()).thenReturn(List.of(violation));
        when(api.requestChangesPR(any())).thenAnswer(i->{rules.setRules(Set.of());return true;});
        publisher.publish(run,"owner");verify(api).requestChangesPR(any());verify(api,never()).blockPR(any());
    }
    @Test void staleOwnerCannotReachScmMutation() throws Exception {
        when(persistence.update(anyString(),anyString(),anyLong(),any())).thenThrow(new AwsSecurityPersistence.LostOwnership());
        assertThrows(AwsSecurityPersistence.LostOwnership.class,()->publisher.publish(run,"owner"));verify(api,never()).approvePR(any());
    }
    // Found on dev: with the failure policy undecided the publisher never ran, so a pull request scan whose AWS review had
    // failed stayed "Running" for ever. An undecided policy must still close the scan as failed, and must still never
    // approve, block or comment on the pull request.
    private void undecided() {
        org.springframework.test.util.ReflectionTestUtils.setField(publisher, "failurePolicy", AwsPrDecision.FailurePolicy.UNDECIDED);
    }
    @Test void anUndecidedPolicyStillClosesTheScanWhenTheReviewFailedAndNeverTouchesThePullRequest() throws Exception {
        undecided();run.stage=AwsSecurityRun.Stage.FAILED;run.providerTerminal=true;run.artifactKey=null;
        var runs=(AwsSecurityRunRepository)org.springframework.test.util.ReflectionTestUtils.getField(publisher,"runs");
        when(runs.findByParentTypeAndAggregatePublishedFalseOrderByCreatedAtAsc(eq("pull_request"),any())).thenReturn(List.of(run));
        when(persistence.claim(eq(run.id),anyString(),anyLong())).thenReturn(Optional.of(run));
        publisher.publishReady();
        verify(scan).setStatus(com.tracelink.appsec.watchtower.core.scan.ScanStatus.FAILED);verify(scan).setRemoteAssessmentState("INCOMPLETE");
        verify(api,never()).approvePR(any());verify(api,never()).requestChangesPR(any());verify(api,never()).blockPR(any());verify(api,never()).sendComment(any(),any());
    }
    // Found on dev: a review that completed, on a pull request that was merged meanwhile, closed its scan as Failed.
    // Nothing failed; the pull request is simply no longer the one that was reviewed.
    @Test void aCompletedReviewOfAPullRequestThatWasResolvedClosesTheScanAsFinishedNotFailed() throws Exception {
        current.setState(PullRequestState.MERGED);
        publisher.publish(run,"owner");
        verify(scan).setStatus(com.tracelink.appsec.watchtower.core.scan.ScanStatus.DONE);verify(scan).setRemoteAssessmentState("SUPERSEDED");
        verify(api,never()).approvePR(any());verify(api,never()).sendComment(any(),any());
    }
    @Test void aFailedReviewOfAPullRequestThatWasResolvedStillClosesTheScanAsFailed() throws Exception {
        current.setState(PullRequestState.MERGED);run.stage=AwsSecurityRun.Stage.FAILED;run.artifactKey=null;
        publisher.publish(run,"owner");
        verify(scan).setStatus(com.tracelink.appsec.watchtower.core.scan.ScanStatus.FAILED);
    }
    @Test void anUndecidedPolicyLeavesACompletedReviewAloneUntilThePolicyIsChosen() throws Exception {
        undecided();
        publisher.publish(run,"owner");
        verify(api,never()).approvePR(any());verify(api,never()).requestChangesPR(any());verify(api,never()).blockPR(any());verify(api,never()).sendComment(any(),any());
        verify(scan,never()).setStatus(any());
    }
    // A run that cannot be published used to return without a trace, so a scan stuck "Running" could not be explained.
    private ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent> logs() {
        var appender=new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>();appender.start();
        ((ch.qos.logback.classic.Logger)org.slf4j.LoggerFactory.getLogger(AwsPrPublisher.class)).addAppender(appender);return appender;
    }
    @Test void aRunThatCannotBePublishedSaysWhyOncePerReason() throws Exception {
        var appender=logs();
        rules.setRules(Set.of());
        publisher.publish(run,"owner");publisher.publish(run,"owner");
        var lines=appender.list.stream().map(e->e.getFormattedMessage()).toList();
        assertEquals(1,lines.size(),lines.toString());
        assertTrue(lines.get(0).contains(run.id)&&lines.get(0).contains("ruleset"),lines.get(0));
    }
    @Test void anExceptionWhilePublishingIsLoggedWithoutProviderDetail() throws Exception {
        var appender=logs();
        when(api.updatePRData(any())).thenThrow(new IllegalStateException("private detail"));
        var runs=(AwsSecurityRunRepository)org.springframework.test.util.ReflectionTestUtils.getField(publisher,"runs");
        when(runs.findByParentTypeAndAggregatePublishedFalseOrderByCreatedAtAsc(eq("pull_request"),any())).thenReturn(List.of(run));
        when(persistence.claim(eq(run.id),anyString(),anyLong())).thenReturn(Optional.of(run));
        publisher.publishReady();
        var lines=appender.list.stream().map(e->e.getFormattedMessage()).toList();
        assertTrue(lines.stream().anyMatch(l->l.contains(run.id)&&l.contains("IllegalStateException")),lines.toString());
        assertFalse(lines.stream().anyMatch(l->l.contains("private detail")));
    }
    @Test void importFailureCannotBePassedByAProviderErrorPolicy() throws Exception {
        org.springframework.test.util.ReflectionTestUtils.setField(publisher, "failurePolicy", AwsPrDecision.FailurePolicy.PASS_ON_ERROR);
        run.stage=AwsSecurityRun.Stage.FAILED; run.artifactKey=null; run.importAttempts=3;
        publisher.publish(run,"owner"); verify(api,never()).approvePR(any()); verify(api,never()).sendComment(any(),any());
    }

    // A pull request scan that waits for AWS is saved as in progress, so the dashboard first counts it when the publisher finishes it.
    private com.tracelink.appsec.watchtower.core.metrics.MetricsProjectionWriter withMetrics(com.tracelink.appsec.watchtower.core.scan.ScanStatus status) {
        var writer=mock(com.tracelink.appsec.watchtower.core.metrics.MetricsProjectionWriter.class);
        org.springframework.test.util.ReflectionTestUtils.setField(publisher,"metrics",writer);
        when(scan.getStatus()).thenReturn(status);when(scan.getId()).thenReturn(11L);when(scan.getEndDateMillis()).thenReturn(1_000_000L);
        return writer;
    }
    @Test void aFinishedReviewCountsTheScanInTheDashboardWithTheTimeAwsKeptItOpen() throws Exception {
        var writer=withMetrics(com.tracelink.appsec.watchtower.core.scan.ScanStatus.DONE);run.terminalAt=1_060_000L;when(api.sendComment(any(),any())).thenReturn(true);
        publisher.publish(run,"owner");
        verify(writer).record(eq("pull_request"),eq(scan),anyList());verify(writer).recordPrPerformance(scan);
        verify(writer).recordProviderWait(11L,1_000_000L,60_000L,true);
    }
    @Test void aFailedReviewIsNotCountedAsACompletedScan() throws Exception {
        var writer=withMetrics(com.tracelink.appsec.watchtower.core.scan.ScanStatus.FAILED);run.stage=AwsSecurityRun.Stage.FAILED;run.artifactKey=null;current.setState(PullRequestState.MERGED);
        publisher.publish(run,"owner");
        verify(writer,never()).record(any(),any(),any());verify(writer,never()).recordProviderWait(anyLong(),anyLong(),anyLong(),anyBoolean());
    }
    @Test void aDashboardFailureNeverUndoesThePublishedResult() throws Exception {
        var writer=withMetrics(com.tracelink.appsec.watchtower.core.scan.ScanStatus.DONE);run.terminalAt=1_060_000L;when(api.sendComment(any(),any())).thenReturn(true);
        var failure=new IllegalStateException("projection down");doThrow(failure).when(writer).record(any(),any(),any());
        publisher.publish(run,"owner");
        verify(scan).setStatus(com.tracelink.appsec.watchtower.core.scan.ScanStatus.DONE);verify(writer).recordFailure("pull_request",failure);
    }
    @Test void theRunKeepsItsOwnFailureReasonWhenTheScanIsClosed() throws Exception {
        run.stage=AwsSecurityRun.Stage.FAILED;run.artifactKey=null;run.statusReason="AWS rejected review update (ValidationException); fields: assets.sourceCode";
        publisher.publish(run,"owner");
        @SuppressWarnings("unchecked") var update=org.mockito.ArgumentCaptor.forClass(java.util.function.Consumer.class);
        verify(persistence,atLeastOnce()).update(eq(run.id),eq("owner"),anyLong(),update.capture());
        for (var action : update.getAllValues()) { @SuppressWarnings("unchecked") java.util.function.Consumer<AwsSecurityRun> change=action; change.accept(run); }
        assertTrue(run.aggregatePublished);assertEquals("AWS rejected review update (ValidationException); fields: assets.sourceCode",run.statusReason);
    }
    @Test void aRunWithNoReasonOfItsOwnStillShowsTheAggregateState() throws Exception {
        run.stage=AwsSecurityRun.Stage.FAILED;run.artifactKey=null;run.statusReason=null;
        publisher.publish(run,"owner");
        @SuppressWarnings("unchecked") var update=org.mockito.ArgumentCaptor.forClass(java.util.function.Consumer.class);
        verify(persistence,atLeastOnce()).update(eq(run.id),eq("owner"),anyLong(),update.capture());
        for (var action : update.getAllValues()) { @SuppressWarnings("unchecked") java.util.function.Consumer<AwsSecurityRun> change=action; change.accept(run); }
        assertEquals("PR aggregate: INCOMPLETE",run.statusReason);
    }
    // When AWS cannot finish: pass the pull request (the default) or keep it incomplete. Both are settings-page choices.
    private void awsFailed(AwsSecurityRun.Stage stage) {
        run.stage=stage;run.artifactKey=null;run.providerTerminal=true;run.providerStatus=null;run.importAttempts=0;run.statusReason="AWS operation unavailable (AccessDeniedException)";
        when(api.sendComment(any(),any())).thenReturn(true);
    }
    private void policy(AwsPrDecision.FailurePolicy policy) {
        org.springframework.test.util.ReflectionTestUtils.setField(publisher,"failurePolicy",policy);
    }
    @Test void aFailedReviewPassesThePullRequestWhenThePolicyIsToPassOnError() throws Exception {
        policy(AwsPrDecision.FailurePolicy.PASS_ON_ERROR);awsFailed(AwsSecurityRun.Stage.FAILED);
        publisher.publish(run,"owner");
        verify(api).approvePR(any());verify(api).sendComment(any(),contains("provider error passed by configured policy"));
        verify(scan).setRemoteAssessmentState("ERROR_PASSED");
    }
    @Test void everyWayAwsCanFailToFinishPassesNotOnlyAFailedJob() throws Exception {
        for (var stage : List.of(AwsSecurityRun.Stage.CANCELED,AwsSecurityRun.Stage.UNAVAILABLE)) {
            clearInvocations(api,scan);policy(AwsPrDecision.FailurePolicy.PASS_ON_ERROR);awsFailed(stage);
            publisher.publish(run,"owner");
            verify(api).approvePR(any());verify(scan).setRemoteAssessmentState("ERROR_PASSED");
        }
    }
    @Test void aFailedReviewStaysIncompleteWhenThePolicyIsToKeepIncomplete() throws Exception {
        policy(AwsPrDecision.FailurePolicy.KEEP_INCOMPLETE);awsFailed(AwsSecurityRun.Stage.FAILED);
        publisher.publish(run,"owner");
        verify(scan).setRemoteAssessmentState("INCOMPLETE");verify(api,never()).approvePR(any());verify(api,never()).sendComment(any(),any());
    }
    @Test void localBlockingFindingsStillBlockWhenAwsFailedAndTheDefaultIsToPass() throws Exception {
        policy(AwsPrDecision.FailurePolicy.PASS_ON_ERROR);awsFailed(AwsSecurityRun.Stage.FAILED);
        var finding=mock(PullRequestViolationEntity.class);when(finding.isNewViolation()).thenReturn(true);when(finding.getEffectiveBlocking()).thenReturn(true);
        when(scan.getViolations()).thenReturn(List.of(finding));when(api.requestChangesPR(any())).thenReturn(true);when(api.blockPR(any())).thenReturn(true);
        publisher.publish(run,"owner");
        verify(api).blockPR(any());verify(api,never()).approvePR(any());
    }
    @Test void thePolicyChosenOnTheSettingsPageOverridesTheDeploymentValue() throws Exception {
        policy(AwsPrDecision.FailurePolicy.PASS_ON_ERROR);awsFailed(AwsSecurityRun.Stage.FAILED);
        var store=mock(AwsSecurityFailurePolicyStore.class);when(store.current()).thenReturn(AwsPrDecision.FailurePolicy.KEEP_INCOMPLETE);
        org.springframework.test.util.ReflectionTestUtils.setField(publisher,"failurePolicies",store);
        publisher.publish(run,"owner");
        verify(scan).setRemoteAssessmentState("INCOMPLETE");verify(api,never()).approvePR(any());
    }
    @Test void aReviewThatReturnedFindingsIsNotAFailureToPass() throws Exception {
        // A failed job can still return evidence; passing is only for reviews that produced nothing to judge.
        policy(AwsPrDecision.FailurePolicy.PASS_ON_ERROR);run.stage=AwsSecurityRun.Stage.PARTIAL;run.providerTerminal=true;
        publisher.publish(run,"owner");
        verify(api,never()).approvePR(any());
    }
    // The pull request's one status comment is finished off with what AWS found and the result (on by default; PR settings switch it).
    private java.util.List<String> statusComments() {
        var texts=org.mockito.ArgumentCaptor.forClass(String.class);
        verify(api,atLeast(0)).sendComment(any(),texts.capture());verify(api,atLeast(0)).updateComment(any(),anyLong(),texts.capture());
        return texts.getAllValues().stream().filter(t->t.contains("Watchtower · scan status")).toList();
    }
    private void statusCommentsOn(boolean enabled) {
        var settings=new com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestSyncSettingsEntity();settings.setStatusCommentsEnabled(enabled);
        var service=mock(com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PullRequestSyncSettingsService.class);when(service.getSettings()).thenReturn(settings);
        org.springframework.test.util.ReflectionTestUtils.setField(publisher,"prSettings",service);
        org.springframework.test.util.ReflectionTestUtils.setField(publisher,"publicUrl","https://wt.example");
        when(api.sendComment(any(),any())).thenReturn(true);
    }
    @Test void aFinishedReviewCompletesTheStatusCommentWithTheFindingsAndResult() throws Exception {
        statusCommentsOn(true);publisher.publish(run,"owner");
        var status=statusComments();
        assertEquals(1,status.size(),status.toString());
        assertTrue(status.get(0).contains("AWS Security Agent:** "),status.get(0));
        assertTrue(status.get(0).contains("Watchtower —"),"the one comment is the scan summary: "+status.get(0));
        assertTrue(status.get(0).contains("https://wt.example/scan/report/latest?"));
        verify(api,never()).sendComment(any(),contains("Watchtower security assessment"));
    }
    @Test void aReviewThatCouldNotFinishSaysSoInTheStatusComment() throws Exception {
        policy(AwsPrDecision.FailurePolicy.PASS_ON_ERROR);awsFailed(AwsSecurityRun.Stage.FAILED);statusCommentsOn(true);
        publisher.publish(run,"owner");
        var status=statusComments();
        assertEquals(1,status.size(),status.toString());
        assertTrue(status.get(0).contains("⚠️ AWS could not finish, passed by policy"));
        assertFalse(status.get(0).contains("|"),status.get(0));
    }
    @Test void aBlockingLocalFindingIsStillListedWhenAwsCouldNotFinish() throws Exception {
        // Dev E2E W03: the summary said "Blocking issues found" and nothing else, so nobody could tell why.
        policy(AwsPrDecision.FailurePolicy.PASS_ON_ERROR);awsFailed(AwsSecurityRun.Stage.FAILED);statusCommentsOn(true);
        var finding=mock(PullRequestViolationEntity.class);when(finding.isNewViolation()).thenReturn(true);when(finding.getEffectiveBlocking()).thenReturn(true);
        when(finding.isBlocking()).thenReturn(true);when(finding.getViolationName()).thenReturn("E2E local block");
        when(finding.getFileName()).thenReturn("w03/local.w03");when(finding.getLineNum()).thenReturn(1);when(finding.getSeverity()).thenReturn(RulePriority.HIGH);
        when(scan.getViolations()).thenReturn(List.of(finding));when(api.requestChangesPR(any())).thenReturn(true);when(api.blockPR(any())).thenReturn(true);
        publisher.publish(run,"owner");
        var status=statusComments();
        assertEquals(1,status.size(),status.toString());
        assertTrue(status.get(0).contains("E2E local block"),status.get(0));
        assertTrue(status.get(0).contains("w03/local.w03:1"),status.get(0));
        assertTrue(status.get(0).contains("AWS Security Agent"),"AWS is named as the scanner that did not finish: "+status.get(0));
    }
    @Test void aLocalFindingGetsItsInlineCommentWhileTheReviewIsRemote() throws Exception {
        // Dev E2E W03: the summary said "Details are on each line" but the core flow stops at "local done, remote running",
        // so no local finding was ever commented on its line.
        policy(AwsPrDecision.FailurePolicy.PASS_ON_ERROR);awsFailed(AwsSecurityRun.Stage.FAILED);statusCommentsOn(true);
        var finding=mock(PullRequestViolationEntity.class);when(finding.isNewViolation()).thenReturn(true);when(finding.getEffectiveBlocking()).thenReturn(true);
        when(finding.isBlocking()).thenReturn(true);when(finding.getViolationName()).thenReturn("E2E local block");
        when(finding.getFileName()).thenReturn("w03/local.w03");when(finding.getLineNum()).thenReturn(1);when(finding.getSeverity()).thenReturn(RulePriority.HIGH);
        when(scan.getViolations()).thenReturn(List.of(finding));when(api.requestChangesPR(any())).thenReturn(true);when(api.blockPR(any())).thenReturn(true);
        when(api.sendInlineComment(any(),anyString(),anyInt(),anyString())).thenReturn(true);
        publisher.publish(run,"owner");
        verify(api).sendInlineComment(eq(current),eq("w03/local.w03"),eq(1),contains("E2E local block"));
        assertFalse(statusComments().get(0).contains("no inline comment"),statusComments().get(0));
    }
    @Test void aReviewOfAReplacedCommitSaysItWasSuperseded() throws Exception {
        statusCommentsOn(true);current.setCommitHash("e".repeat(40));
        publisher.publish(run,"owner");
        var status=statusComments();
        assertEquals(1,status.size(),status.toString());
        assertTrue(status.get(0).contains("A newer commit replaced this one"));
    }
    @Test void bitbucketReportsAbbreviatedCommitsAndTheReviewIsStillCurrent() throws Exception {
        statusCommentsOn(true);
        var snapshot=AwsSecuritySnapshot.decode(run.snapshotJson);
        current.setCommitHash(snapshot.context().commit().substring(0,12));current.setBaseCommitHash(snapshot.context().baseCommit().substring(0,12));
        publisher.publish(run,"owner");
        verify(api).approvePR(any());
        var status=statusComments();
        assertEquals(1,status.size(),status.toString());
        assertFalse(status.get(0).contains("A newer commit replaced this one"),status.get(0));
    }
    @Test void noStatusCommentIsPostedWhenTheSettingIsOff() throws Exception {
        statusCommentsOn(false);publisher.publish(run,"owner");
        assertTrue(statusComments().isEmpty());
    }
    // AWS findings on changed lines are commented on those lines (severity, plain title, report link) before the review state is set.
    private AwsSecurityArtifact.Occurrence occurrence(String severity,String name,String file,int line) {
        var snapshot=AwsSecuritySnapshot.decode(run.snapshotJson);
        var details=new AwsSecurityFindingMapper().map(AwsSecurityImporterTest.finding("id-"+line).toBuilder().riskLevel(severity).name(name).build(),snapshot,"review","job");
        return new AwsSecurityArtifact.Occurrence("key"+line,details,List.of(new com.tracelink.appsec.watchtower.core.scan.code.report.ProviderFindingDetails.Location(file,line,line,"changed")));
    }
    private void awsReturns(AwsSecurityArtifact.Occurrence... findings) throws Exception {
        var importer=(AwsSecurityImporter)org.springframework.test.util.ReflectionTestUtils.getField(publisher,"importer");
        var snapshot=AwsSecuritySnapshot.decode(run.snapshotJson);
        var manifest=new AwsSecurityArtifact(1,run.id,snapshot,"COMPLETED","COMPLETE",1,findings.length,findings.length,List.of(),List.of(),30,List.of("page-0"),null,Map.of(),Map.of());
        when(importer.manifest("manifest")).thenReturn(manifest);when(importer.page(manifest,0)).thenReturn(List.of(findings));
    }
    @Test void aNonBlockingAwsFindingIsCommentedOnItsChangedLine() throws Exception {
        statusCommentsOn(true);awsReturns(occurrence("LOW","Verbose error output","src/b.java",10));
        publisher.publish(run,"owner");
        var text=org.mockito.ArgumentCaptor.forClass(String.class);
        verify(api).sendInlineComment(eq(current),eq("src/b.java"),eq(10),text.capture());
        assertTrue(text.getValue().startsWith("⚠️ **Low · "),text.getValue());
        assertTrue(text.getValue().contains("not blocking · AWS Security Agent"));
        assertTrue(text.getValue().contains("https://wt.example/scan/report/latest?"));
        assertTrue(text.getValue().contains("_Watchtower · aws ref "));
        verify(api).approvePR(any());
    }
    @Test void aBlockingAwsFindingIsMarkedBlockingAndStillBlocksThePullRequest() throws Exception {
        statusCommentsOn(true);when(api.requestChangesPR(any())).thenReturn(true);when(api.blockPR(any())).thenReturn(true);
        awsReturns(occurrence("HIGH","Command execution","src/b.java",12));
        publisher.publish(run,"owner");
        verify(api).sendInlineComment(eq(current),eq("src/b.java"),eq(12),startsWith("⛔ **High · "));
        verify(api).blockPR(any());verify(api,never()).approvePR(any());
    }
    @Test void aFindingThatLooksLikeASecretGetsAGenericTitleNotTheProvidersWords() throws Exception {
        statusCommentsOn(true);awsReturns(occurrence("LOW","Slack bot token and RSA private key committed to source control","src/c.py",4));
        publisher.publish(run,"owner");
        var text=org.mockito.ArgumentCaptor.forClass(String.class);
        verify(api).sendInlineComment(eq(current),eq("src/c.py"),eq(4),text.capture());
        assertTrue(text.getValue().contains("Possible secret or credential"),text.getValue());
        assertFalse(text.getValue().toLowerCase().contains("slack")||text.getValue().toLowerCase().contains("rsa"),text.getValue());
    }
    @Test void noFindingCommentsAreWrittenWhenTheSettingIsOff() throws Exception {
        statusCommentsOn(false);awsReturns(occurrence("LOW","Verbose error output","src/b.java",10));
        publisher.publish(run,"owner");
        verify(api,never()).sendInlineComment(any(),anyString(),anyInt(),anyString());verify(api).approvePR(any());
    }
    @Test void theFinalCommentListsWhatAwsFoundWorstFirstWithoutProviderWords() throws Exception {
        statusCommentsOn(true);when(api.requestChangesPR(any())).thenReturn(true);when(api.blockPR(any())).thenReturn(true);
        awsReturns(occurrence("LOW","Verbose error output","src/b.java",10),occurrence("HIGH","Command execution","src/b.java",12),
            occurrence("LOW","Slack bot token and RSA private key committed to source control","src/c.py",4));
        publisher.publish(run,"owner");
        var comment=statusComments().getFirst();
        assertTrue(comment.contains("**AWS findings**"),comment);
        assertTrue(comment.indexOf("`src/b.java:12`")<comment.indexOf("`src/b.java:10`"),"blocking and worst first: "+comment);
        assertFalse(comment.contains("Command execution")||comment.contains("Verbose error output"),"the provider's own titles are not retained or posted: "+comment);
        assertTrue(comment.contains("| ⛔ High |"),comment);
        assertTrue(comment.contains("`src/b.java:12`"),comment);
        assertTrue(comment.contains("Possible secret or credential"),comment);
        assertFalse(comment.toLowerCase().contains("slack")||comment.toLowerCase().contains("rsa"),comment);
    }
    @Test void onlyTheTopTenAwsFindingsAreListedAndTheTotalIsCounted() throws Exception {
        statusCommentsOn(true);
        var many=new AwsSecurityArtifact.Occurrence[14];
        for(int i=0;i<many.length;i++)many[i]=occurrence("LOW","Verbose error output "+i,"src/b.java",10+i);
        awsReturns(many);
        publisher.publish(run,"owner");
        var comment=statusComments().getFirst();
        assertTrue(comment.contains("**AWS findings: top 10 of 14**"),comment);
        assertTrue(comment.contains("…and 4 more in the [full report]"),comment);
        assertEquals(10,comment.lines().filter(l->l.startsWith("| ⚠️ Low |")).count(),comment);
    }
    @Test void aFailureCommentingFindingsNeverStopsTheReviewStateFromBeingSet() throws Exception {
        statusCommentsOn(true);awsReturns(occurrence("LOW","Verbose error output","src/b.java",10));
        when(api.listComments(any())).thenThrow(new IllegalStateException("scm down"));
        publisher.publish(run,"owner");
        verify(api).approvePR(any());
    }
}
