package com.tracelink.appsec.module.awssecurity;

import java.util.*;
import java.util.function.Consumer;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import com.tracelink.appsec.watchtower.core.module.ModuleControlService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import software.amazon.awssdk.services.securityagent.model.*;

class AwsSecurityCoordinatorTest {
    AwsSecurityRun run; AwsSecurityPersistence persistence; AwsSecurityClientGateway gateway; AwsSecurityInputStore inputs;
    AwsSecurityImporter importer; AwsSecurityScanCoordinator coordinator;
    AwsSecurityRunRepository runRepository;ApiIntegrationService sourceIntegrations;ModuleControlService moduleControls;AwsSecurityRepositorySettingsRepository repositoryPermissions;AwsSecurityRepoReviews repoReviews;
    @BeforeEach void setup() {
        repoReviews=mock(AwsSecurityRepoReviews.class);when(repoReviews.holds(anyLong(),anyString(),anyLong())).thenReturn(true);
        run=AwsTestSupport.run();run.stage=AwsSecurityRun.Stage.INPUT_READY;run.reviewId=null;run.jobId=null;run.providerTerminal=false;
        run.sourceKey="aws-security-inputs/test/one/source.zip";run.diffKey="aws-security-inputs/test/one/changes.diff";
        persistence=mock(AwsSecurityPersistence.class);gateway=mock(AwsSecurityClientGateway.class);inputs=mock(AwsSecurityInputStore.class);importer=mock(AwsSecurityImporter.class);
        var runs=mock(AwsSecurityRunRepository.class);runRepository=runs;when(runs.findById(run.id)).thenAnswer(i->Optional.of(run));
        when(persistence.claim(eq(run.id),anyString(),anyLong())).thenAnswer(i->{run.owner=i.getArgument(1);run.fence++;run.leaseUntil=System.currentTimeMillis()+180000;return Optional.of(run);});
        when(persistence.update(eq(run.id),anyString(),anyLong(),any())).thenAnswer(i->{Consumer<AwsSecurityRun> change=i.getArgument(3);change.accept(run);return run;});
        var controls=mock(ModuleControlService.class);when(controls.enabled(AwsSecurityModule.NAME)).thenReturn(true);
        var repositorySettings=mock(AwsSecurityRepositorySettingsRepository.class);var permission=new AwsSecurityRepositorySettings();permission.permission=AwsSecurityRepositorySettings.Permission.ENABLED;when(repositorySettings.findById(anyLong())).thenReturn(Optional.of(permission));
        sourceIntegrations=mock(ApiIntegrationService.class);moduleControls=controls;repositoryPermissions=repositorySettings;
        coordinator=new AwsSecurityScanCoordinator(persistence,runs,gateway,inputs,importer,sourceIntegrations,AwsTestSupport.settings(),controls,repositorySettings,repoReviews);
    }
    @Test void aFailureBeforeAnyAwsCallIsNotBlamedOnAws() {
        run.stage=AwsSecurityRun.Stage.QUEUED;
        when(sourceIntegrations.findByLabel(anyString())).thenReturn(null);
        assertTrue(coordinator.run(run.id,()->{},System.currentTimeMillis()+60000));
        assertEquals(AwsSecurityRun.Stage.FAILED,run.stage);
        assertTrue(run.statusReason.startsWith("Source preparation failed (IOException)"),run.statusReason);
        assertFalse(run.statusReason.contains("AWS operation unavailable"));
    }
    @Test void aSourceOverTheSizeLimitSaysSoInsteadOfNamingAClass() {
        String reason = AwsSecurityScanCoordinator.sourcePreparationReason(new AwsSecurityInputStore.SourceLimitExceeded());
        assertTrue(reason.contains("over the AWS size limits"), reason);
        assertTrue(reason.contains("8 MB per file"), reason);
        assertTrue(reason.contains("no AWS call was made"), reason);
        assertFalse(reason.contains("IOException"), reason);
        // any other preparation failure keeps the stage and class text
        assertTrue(AwsSecurityScanCoordinator.sourcePreparationReason(new java.io.IOException("x"))
            .startsWith("Source preparation failed (IOException)"));
    }
    @Test void aFileOverTheSizeLimitIsRefusedWithTheLimitException() throws Exception {
        var directory = java.nio.file.Files.createTempDirectory("aws-limit-test");
        var archive = java.nio.file.Files.createTempFile("aws-limit-test", ".zip");
        try {
            java.nio.file.Files.write(directory.resolve("big.txt"), new byte[(int) AwsSecurityInputStore.MAX_FILE + 1]);
            org.junit.jupiter.api.Assertions.assertThrows(AwsSecurityInputStore.SourceLimitExceeded.class,
                () -> AwsSecurityInputStore.archive(directory, archive));
        } finally {
            java.nio.file.Files.deleteIfExists(directory.resolve("big.txt"));
            java.nio.file.Files.deleteIfExists(directory);
            java.nio.file.Files.deleteIfExists(archive);
        }
    }
    @Test void scannerOffCancelsBeforeAnyProviderSubmission() {
        when(moduleControls.enabled(AwsSecurityModule.NAME)).thenReturn(false);
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        assertEquals(AwsSecurityRun.Stage.CANCELED,run.stage);verifyNoInteractions(gateway);
    }
    @Test void workerInterruptionKeepsTheAwsJobAndRecoveryImportsThatSameJob() throws Exception {
        run.stage=AwsSecurityRun.Stage.RUNNING;run.reviewId="review";run.jobId="job";
        when(gateway.job(any(),eq("review"),eq("job"))).thenAnswer(i->{
            Thread.currentThread().interrupt();return CodeReviewJob.builder().status("IN_PROGRESS").build();
        });
        try {
            assertFalse(coordinator.run(run.id,()->{},System.currentTimeMillis()+60000));
            assertTrue(Thread.currentThread().isInterrupted());assertFalse(run.stopRequested);
            assertEquals(AwsSecurityRun.Stage.RUNNING,run.stage);assertFalse(run.providerTerminal);
            verify(gateway,never()).stop(any(),anyString());verify(inputs,never()).delete(any(),any(),any());
        } finally {Thread.interrupted();}
        when(gateway.job(any(),eq("review"),eq("job"))).thenReturn(CodeReviewJob.builder().status("COMPLETED").build());
        var manifest=new AwsSecurityArtifact(1,run.id,AwsSecuritySnapshot.decode(run.snapshotJson),"COMPLETED","COMPLETE",1,0,0,List.of(),List.of(),30,List.of(),null,Map.of(),Map.of());
        when(importer.importAll(eq(run),any())).thenReturn(new AwsSecurityImporter.Imported("saved/manifest",manifest));
        assertTrue(coordinator.run(run.id,()->{},System.currentTimeMillis()+60000));
        assertEquals(AwsSecurityRun.Stage.COMPLETE,run.stage);assertTrue(run.cleanupComplete);
        verify(gateway,never()).create(any(),anyString(),anyString());verify(gateway,never()).start(any(),anyString(),any());
    }
    @Test void runningAwsJobSchedulesAnotherPollWithoutKeepingTheWorker() {
        run.stage = AwsSecurityRun.Stage.RUNNING; run.reviewId = "review"; run.jobId = "job";
        when(gateway.job(any(), eq("review"), eq("job")))
            .thenReturn(CodeReviewJob.builder().status("IN_PROGRESS").build());
        long started = System.currentTimeMillis();
        assertTrue(coordinator.run(run.id, () -> { }, started + 60_000));
        assertEquals(AwsSecurityRun.Stage.RUNNING, run.stage);
        assertTrue(run.dueAt >= started + 15_000 && run.dueAt < System.currentTimeMillis() + 20_000);
        verify(gateway, times(1)).job(any(), eq("review"), eq("job"));
    }
    @Test void scannerOffStopsAnActiveJobAndKeepsInputsUntilTerminalProof() {
        run.stage=AwsSecurityRun.Stage.RUNNING;run.reviewId="review";run.jobId="job";
        when(moduleControls.enabled(AwsSecurityModule.NAME)).thenReturn(false);
        when(gateway.job(any(),eq("review"),eq("job"))).thenThrow(new IllegalStateException("Provider terminal status temporarily unavailable"));
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        verify(gateway).stop(any(),eq("job"));assertTrue(run.stopRequested);assertFalse(run.providerTerminal);
        verify(inputs,never()).delete(any(),any(),any());
    }
    @Test void finishedReviewsRemainInAwsEvenAfterTheFormerRetentionWindow() {
        run.stage=AwsSecurityRun.Stage.COMPLETE;run.reviewId="review";run.jobId="job";run.providerTerminal=true;run.terminalAt=1;
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        assertTrue(run.cleanupComplete);assertFalse(run.providerDeleted);assertEquals(Long.MAX_VALUE,run.dueAt);verify(gateway,never()).retire(any(),anyString());
    }
    @Test void sampleReviewsAreAlsoKeptAfterResultsAreSaved() {
        run.parentType="setup";run.stage=AwsSecurityRun.Stage.COMPLETE;run.reviewId="review";run.jobId="job";run.providerTerminal=true;run.artifactKey="saved";run.terminalAt=1;
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        assertTrue(run.cleanupComplete);assertFalse(run.providerDeleted);verify(gateway,never()).retire(any(),anyString());
    }
    @Test void acceptedCreateTimeoutIsReconciledWithoutCreatingAgain() throws Exception {
        when(gateway.create(any(),anyString(),anyString())).thenThrow(new IllegalStateException("accepted request timed out"));
        assertTrue(coordinator.run(run.id,()->{},System.currentTimeMillis()+60000));
        assertEquals(AwsSecurityRun.Stage.CREATING,run.stage);assertTrue(run.needsReconciliation);verify(inputs,never()).delete(any(),any(),any());
        when(gateway.reconcileCreate(any(),anyString(),anyString())).thenReturn(Optional.empty());
        assertTrue(coordinator.run(run.id,()->{},System.currentTimeMillis()+60000));verify(gateway,times(1)).create(any(),anyString(),anyString());verify(gateway,never()).start(any(),any(),any());
    }
    @Test void preFixReviewNamesRemainDiscoverableWithoutCreatingAnotherReview() {
        run.stage=AwsSecurityRun.Stage.CREATING;
        when(gateway.reconcileCreate(any(),eq(AwsSecurityIdentity.legacyReviewTitle(run)),anyString())).thenReturn(Optional.of("legacy-review"));
        when(gateway.start(any(),eq("legacy-review"),any())).thenThrow(new IllegalStateException("uncertain start"));
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        assertEquals("legacy-review",run.reviewId);assertEquals(AwsSecurityRun.Stage.STARTING,run.stage);
        verify(gateway,never()).create(any(),anyString(),anyString());
    }
    @Test void rejectedCreateFailsAndCleansInputsInsteadOfHoldingCapacityForANonexistentReview() {
        when(gateway.create(any(),anyString(),anyString())).thenThrow(ValidationException.builder()
            .message("source-bearing provider detail must not be retained")
            .fieldList(ValidationExceptionField.builder().path("title").message("secret-value").build(),
                ValidationExceptionField.builder().path("source-secret-value").build()).build());
        assertTrue(coordinator.run(run.id,()->{},System.currentTimeMillis()+60000));
        assertEquals(AwsSecurityRun.Stage.FAILED,run.stage);assertTrue(run.providerTerminal);
        assertFalse(run.needsReconciliation);assertTrue(run.cleanupComplete);assertFalse(run.remotePossible());
        assertNull(run.reviewId);assertNull(run.jobId);assertTrue(run.statusReason.contains("fields: title"));
        assertFalse(run.statusReason.contains("secret"));assertFalse(run.statusReason.contains("source-bearing"));
        verify(gateway,never()).reconcileCreate(any(),anyString(),anyString());verify(gateway,never()).start(any(),anyString(),any());
        verify(inputs).delete(any(),eq(run.sourceKey),any());
        verify(persistence).release(eq(run.id),anyString(),eq(run.fence));
    }
    @Test void rejectedStartKeepsTheReviewButProvesThereIsNoRunningJob() {
        run.stage=AwsSecurityRun.Stage.REVIEW_READY;run.reviewId="review";
        when(gateway.start(any(),anyString(),any())).thenThrow(ValidationException.builder().message("private detail").build());
        assertTrue(coordinator.run(run.id,()->{},System.currentTimeMillis()+60000));
        assertEquals(AwsSecurityRun.Stage.FAILED,run.stage);assertTrue(run.providerTerminal);assertTrue(run.cleanupComplete);
        assertEquals("review",run.reviewId);assertNull(run.jobId);assertFalse(run.needsReconciliation);
        assertTrue(run.statusReason.contains("job start"));verify(gateway,never()).retire(any(),anyString());
    }
    // Found on dev: AWS refused a job start and the reason named no field, because AWS reports nested paths such as
    // "diffSource.s3Uri" and only the exact top-level names were kept. A nested path under a known field is a schema
    // name and is safe to show; anything else is still dropped.
    @Test void aRejectedStartNamesTheNestedSchemaFieldButNothingElse() {
        run.stage=AwsSecurityRun.Stage.REVIEW_READY;run.reviewId="review";
        when(gateway.start(any(),anyString(),any())).thenThrow(ValidationException.builder().message("private detail")
            .fieldList(ValidationExceptionField.builder().path("diffSource.s3Uri").message("secret-value").build(),
                ValidationExceptionField.builder().path("diffSource.s3Uri").build(),
                ValidationExceptionField.builder().path("unknown.field").build(),
                ValidationExceptionField.builder().path("diffSource.not a path!").build()).build());
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        assertTrue(run.statusReason.contains("job start"));
        assertTrue(run.statusReason.endsWith("fields: diffSource.s3Uri"),run.statusReason);
        assertFalse(run.statusReason.contains("secret"));assertFalse(run.statusReason.contains("unknown"));assertFalse(run.statusReason.contains("not a path"));
    }
    @Test void theObservedTitleValidationErrorHasASafeExplanationForTheReport() {
        when(gateway.create(any(),anyString(),anyString())).thenThrow(ValidationException.builder()
            .message("Title can only contain letters, numbers, hyphens, and underscores. Maximum 100 characters allowed. secret-extra-detail").build());
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        assertTrue(run.statusReason.contains("review titles allow letters, numbers, hyphens and underscores, up to 100 characters"));
        assertFalse(run.statusReason.contains("secret-extra-detail"));assertTrue(run.cleanupComplete);
    }
    @Test void validationFailureDuringReconciliationDoesNotProveTheOriginalMutationWasRejected() {
        run.stage=AwsSecurityRun.Stage.CREATING;
        when(gateway.reconcileCreate(any(),anyString(),anyString())).thenThrow(ValidationException.builder().message("read rejected").build());
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        assertEquals(AwsSecurityRun.Stage.CREATING,run.stage);assertTrue(run.needsReconciliation);assertFalse(run.providerTerminal);
        verify(inputs,never()).delete(any(),any(),any());verify(gateway,never()).create(any(),anyString(),anyString());
    }
    @Test void acceptedStartTimeoutKeepsReviewAndDoesNotBlindlyStartAgain() {
        run.stage=AwsSecurityRun.Stage.REVIEW_READY;run.reviewId="review";
        when(gateway.start(any(),anyString(),any())).thenThrow(new IllegalStateException("accepted request timed out"));
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);assertEquals(AwsSecurityRun.Stage.STARTING,run.stage);assertEquals("review",run.reviewId);
        when(gateway.reconcileStart(any(),eq("review"))).thenReturn(Optional.empty());
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);verify(gateway,times(1)).start(any(),anyString(),any());
    }
    @Test void failedStopNeverDeletesInputOrClaimsProviderTerminal() {
        run.stage=AwsSecurityRun.Stage.RUNNING;run.reviewId="review";run.jobId="job";run.deadlineAt=1;
        doThrow(new IllegalStateException("stop denied")).when(gateway).stop(any(),eq("job"));
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        assertTrue(run.stopRequested);assertTrue(run.needsReconciliation);assertFalse(run.providerTerminal);assertEquals(AwsSecurityRun.Stage.RUNNING,run.stage);
        verify(inputs,never()).delete(any(),any(),any());
    }
    @Test void cleanupDeniedIsDurableAndRetriedWithoutReplacingJob() {
        run.stage=AwsSecurityRun.Stage.COMPLETE;run.reviewId="review";run.jobId="job";run.providerTerminal=true;
        doThrow(new IllegalStateException("delete denied")).doNothing().when(inputs).delete(any(),eq(run.sourceKey),isNull());
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);assertFalse(run.cleanupComplete);assertEquals(1,run.cleanupAttempts);
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);assertTrue(run.cleanupComplete);assertEquals(2,run.cleanupAttempts);
        verify(gateway,never()).start(any(),any(),any());verify(gateway,never()).create(any(),any(),any());
    }
    @Test void completedDuringOutageIsImportedEvenAfterTheLocalDeadlineWithoutStoppingIt() throws Exception {
        run.stage=AwsSecurityRun.Stage.RUNNING;run.reviewId="review";run.jobId="job";run.deadlineAt=1;
        when(moduleControls.enabled(AwsSecurityModule.NAME)).thenReturn(false);
        when(gateway.job(any(),eq("review"),eq("job"))).thenReturn(CodeReviewJob.builder().status("COMPLETED").build());
        var manifest=new AwsSecurityArtifact(1,run.id,AwsSecuritySnapshot.decode(run.snapshotJson),"COMPLETED","COMPLETE",1,0,0,List.of(),List.of(),30,List.of(),null,Map.of(),Map.of());
        when(importer.importAll(eq(run),any())).thenReturn(new AwsSecurityImporter.Imported("immutable/manifest",manifest));
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        assertTrue(run.providerTerminal);assertEquals(AwsSecurityRun.Stage.COMPLETE,run.stage);assertTrue(run.cleanupComplete);
        verify(gateway).job(any(),eq("review"),eq("job"));
        verify(gateway,never()).stop(any(),anyString());
    }
    @Test void publishedImportIsImmutableAndTerminalCleanupDoesNotRerunImport() throws Exception {
        run.stage=AwsSecurityRun.Stage.IMPORTING;run.reviewId="review";run.jobId="job";run.providerTerminal=true;
        var manifest=new AwsSecurityArtifact(1,run.id,AwsSecuritySnapshot.decode(run.snapshotJson),"COMPLETED","COMPLETE",1,0,0,List.of(),List.of(),30,List.of(),null,Map.of(),Map.of());
        when(importer.importAll(eq(run),any())).thenReturn(new AwsSecurityImporter.Imported("immutable/manifest",manifest));
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);assertEquals(AwsSecurityRun.Stage.COMPLETE,run.stage);assertEquals("immutable/manifest",run.artifactKey);assertTrue(run.cleanupComplete);
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);verify(importer,times(1)).importAll(eq(run),any());
    }
    @Test void repeatedTerminalImportFailureBecomesRecoverableFailureAndAllowsCleanup() throws Exception {
        run.stage=AwsSecurityRun.Stage.IMPORTING; run.reviewId="review"; run.jobId="job"; run.providerTerminal=true;
        when(importer.importAll(any(),any())).thenThrow(new java.io.IOException("payload must not be retained"));
        for(int i=0;i<3;i++) coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        assertEquals(AwsSecurityRun.Stage.FAILED,run.stage); assertEquals(3,run.importAttempts); assertNull(run.artifactKey);
        assertFalse(run.statusReason.contains("payload"));
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        assertTrue(run.cleanupComplete); verify(inputs).delete(any(),eq(run.sourceKey),any());
    }

    @Test void evidenceBoundPersistsPartialCountsInsteadOfAnEmptySuccessfulReport() throws Exception {
        run.stage=AwsSecurityRun.Stage.IMPORTING; run.reviewId="review"; run.jobId="job"; run.providerTerminal=true;
        when(importer.importAll(any(),any())).thenThrow(new AwsSecurityImporter.ImportLimitExceeded(700,"MANIFEST_BYTES"));
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        assertEquals(AwsSecurityRun.Stage.PARTIAL,run.stage); assertEquals(0,run.importedCount); assertEquals(700,run.missingCount);
        assertNull(run.artifactKey); assertTrue(run.statusReason.contains("MANIFEST_BYTES")); assertFalse(run.reference().status().complete());
    }

    @Test void setupUsesOnlyPackagedSourceWhileScannerAndRepositoryPermissionAreOff() throws Exception {
        run.parentType="setup";run.setupMode=AwsSecuritySetupMode.FULL;run.setupRequester="engineer";
        run.stage=AwsSecurityRun.Stage.QUEUED;run.sourceKey=null;run.diffKey=null;
        var s=AwsTestSupport.settings();
        var off=new AwsSecuritySettings(s.region(),s.account(),s.spaceId(),s.serviceRole(),s.inputBucket(),s.kmsKey(),s.logGroup(),s.installation(),s.queueUrl(),s.reviewSeconds());
        when(moduleControls.enabled(anyString())).thenReturn(false);when(repositoryPermissions.findById(anyLong())).thenReturn(Optional.empty());
        coordinator=new AwsSecurityScanCoordinator(persistence,runRepository,gateway,inputs,importer,sourceIntegrations,off,moduleControls,repositoryPermissions,repoReviews);
        var access=mock(AwsSecuritySetupAccess.class);when(access.allowed("engineer")).thenReturn(true);coordinator.setSetupAccess(access);
        when(inputs.put(any(),anyString(),any(),anyString())).thenAnswer(i->{
            try(var zip=new java.util.zip.ZipInputStream(java.nio.file.Files.newInputStream(i.getArgument(2)))){
                assertEquals("app.py",zip.getNextEntry().getName());
                assertTrue(new String(zip.readAllBytes(),java.nio.charset.StandardCharsets.UTF_8).contains("request.args[\"command\"]"));
            }return "source-version";
        });
        when(gateway.create(any(),anyString(),anyString())).thenThrow(new IllegalStateException("stop at submission boundary"));
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        assertTrue(run.inputsVerified);assertEquals(1,run.sourceFiles);assertNull(run.diffKey);
        assertTrue(run.needsReconciliation);verify(gateway).create(any(),eq(AwsSecurityIdentity.reviewTitle(run)),contains("/"+run.id+"/1/source.zip"));
        verifyNoInteractions(sourceIntegrations,repositoryPermissions);
    }
    // Found on dev: AWS refused every differential start with "diffSource.s3Uri must point to a .patch file" because the
    // object was named changes.diff, so no pull request review could ever start.
    @Test void theDifferentialInputIsUploadedAsAPatchFileBecauseAwsRefusesAnyOtherExtension() throws Exception {
        run.parentType="setup";run.setupMode=AwsSecuritySetupMode.DIFFERENTIAL;run.setupRequester="engineer";
        run.stage=AwsSecurityRun.Stage.QUEUED;run.sourceKey=null;run.diffKey=null;
        var s=AwsTestSupport.settings();
        var off=new AwsSecuritySettings(s.region(),s.account(),s.spaceId(),s.serviceRole(),s.inputBucket(),s.kmsKey(),s.logGroup(),s.installation(),s.queueUrl(),s.reviewSeconds());
        when(moduleControls.enabled(anyString())).thenReturn(false);when(repositoryPermissions.findById(anyLong())).thenReturn(Optional.empty());
        coordinator=new AwsSecurityScanCoordinator(persistence,runRepository,gateway,inputs,importer,sourceIntegrations,off,moduleControls,repositoryPermissions,repoReviews);
        var access=mock(AwsSecuritySetupAccess.class);when(access.allowed("engineer")).thenReturn(true);coordinator.setSetupAccess(access);
        when(inputs.put(any(),anyString(),any(),anyString())).thenReturn("version");
        when(gateway.create(any(),anyString(),anyString())).thenThrow(new IllegalStateException("stop at submission boundary"));
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        assertNotNull(run.diffKey);assertTrue(run.diffKey.endsWith("/changes.patch"),run.diffKey);
        verify(inputs).put(any(),eq(run.diffKey),any(),anyString());
        verify(inputs,never()).put(any(),endsWith(".diff"),any(),anyString());
    }
    // ---- one AWS review per repository, shared by its scans (each scan points it at its own source, then starts its own job)
    private String ownSource(){return AwsSecurityScanCoordinator.uri(AwsSecuritySnapshot.decode(run.snapshotJson).profile(),run.sourceKey);}
    private void shared(){run.sharedReview=true;run.repositoryId=2;}
    private void lockFree(String reviewOrNull){when(repoReviews.acquire(eq(2L),anyString(),anyString(),eq(run.id),anyLong())).thenReturn(new AwsSecurityRepoReviews.Claim(true,reviewOrNull));}
    @Test void theFirstScanOfARepositoryCreatesItsReviewUnderTheRepositoryTitleAndRemembersIt() {
        shared();lockFree(null);
        when(gateway.findReviewByTitle(any(),anyString())).thenReturn(Optional.empty());
        when(gateway.create(any(),anyString(),eq(ownSource()))).thenReturn("cr-1");
        when(gateway.start(any(),eq("cr-1"),any())).thenReturn("job-1");
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        assertEquals(AwsSecurityRun.Stage.RUNNING,run.stage);assertEquals("cr-1",run.reviewId);assertEquals("job-1",run.jobId);
        verify(gateway).create(any(),eq(AwsSecurityIdentity.repositoryReviewTitle(run)),eq(ownSource()));
        verify(repoReviews).recordReview(2L,run.id,"cr-1");
        verify(gateway,never()).updateSource(any(),anyString(),anyString());
        verify(repoReviews).release(2L,run.id);
    }
    @Test void theNextScanReusesTheReviewAndOnlyPointsItAtItsOwnSource() {
        shared();lockFree("cr-1");
        when(gateway.start(any(),eq("cr-1"),any())).thenReturn("job-2");
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        assertEquals("cr-1",run.reviewId);assertEquals("job-2",run.jobId);assertEquals(AwsSecurityRun.Stage.RUNNING,run.stage);
        verify(gateway).updateSource(any(),eq("cr-1"),eq(ownSource()));
        verify(gateway,never()).create(any(),anyString(),anyString());verify(gateway,never()).findReviewByTitle(any(),anyString());
        verify(repoReviews).release(2L,run.id);
    }
    @Test void aScanWaitsWithoutTouchingAwsWhileAnotherScanOfTheSameRepositoryHoldsTheLock() {
        shared();when(repoReviews.acquire(eq(2L),anyString(),anyString(),eq(run.id),anyLong())).thenReturn(AwsSecurityRepoReviews.Claim.WAITING);
        long before=System.currentTimeMillis();
        assertTrue(coordinator.run(run.id,()->{},before+60000));
        assertEquals(AwsSecurityRun.Stage.INPUT_READY,run.stage);assertTrue(run.dueAt>before,"it is woken later, not busy-looped");
        assertTrue(run.statusReason.contains("Waiting"),run.statusReason);
        verifyNoInteractions(gateway);verify(repoReviews,never()).release(anyLong(),anyString());
    }
    @Test void aReviewDeletedInAwsIsForgottenAndTheScanCreatesAFreshOne() {
        shared();lockFree("cr-gone");
        doThrow(ResourceNotFoundException.builder().message("gone").build()).when(gateway).updateSource(any(),eq("cr-gone"),anyString());
        when(gateway.findReviewByTitle(any(),anyString())).thenReturn(Optional.empty());
        when(gateway.create(any(),anyString(),anyString())).thenReturn("cr-2");when(gateway.start(any(),eq("cr-2"),any())).thenReturn("job-3");
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        verify(repoReviews).forgetReview(2L,run.id);verify(repoReviews).recordReview(2L,run.id,"cr-2");
        assertEquals("cr-2",run.reviewId);assertEquals("job-3",run.jobId);
    }
    @Test void aRuntimeRoleWithoutUpdatePermissionFallsBackToTheScansOwnReviewAndFreesTheLock() {
        shared();lockFree("cr-1");run.needsReconciliation=true;run.statusReason="AWS operation unavailable (AccessDeniedException); inspect stage and reconcile";
        doThrow(software.amazon.awssdk.awscore.exception.AwsServiceException.builder().statusCode(403).message("denied")
            .awsErrorDetails(software.amazon.awssdk.awscore.exception.AwsErrorDetails.builder().errorCode("AccessDeniedException").build()).build())
            .when(gateway).updateSource(any(),eq("cr-1"),anyString());
        when(gateway.create(any(),eq(AwsSecurityIdentity.reviewTitle(run)),anyString())).thenReturn("cr-own");when(gateway.start(any(),eq("cr-own"),any())).thenReturn("job-own");
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        assertFalse(run.sharedReview,"the scan no longer claims to share a review");assertFalse(run.needsReconciliation);assertNull(run.statusReason);assertEquals("cr-own",run.reviewId);assertEquals("job-own",run.jobId);
        verify(repoReviews,atLeastOnce()).release(2L,run.id);verify(repoReviews,never()).recordReview(anyLong(),anyString(),anyString());
    }
    @Test void aReviewTheMappingForgotIsAdoptedByTitleInsteadOfCreatingADuplicate() {
        shared();lockFree(null);
        when(gateway.findReviewByTitle(any(),eq(AwsSecurityIdentity.repositoryReviewTitle(run)))).thenReturn(Optional.of("cr-orphan"));
        when(gateway.start(any(),eq("cr-orphan"),any())).thenReturn("job-4");
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        verify(gateway).updateSource(any(),eq("cr-orphan"),eq(ownSource()));verify(gateway,never()).create(any(),anyString(),anyString());
        verify(repoReviews).recordReview(2L,run.id,"cr-orphan");assertEquals("job-4",run.jobId);
    }
    @Test void aScanThatLostTheLockBeforeStartingMustReacquireItInsteadOfStartingOnSomeoneElsesSource() {
        shared();run.stage=AwsSecurityRun.Stage.REVIEW_READY;run.reviewId="cr-1";
        when(repoReviews.holds(eq(2L),eq(run.id),anyLong())).thenReturn(false);
        when(repoReviews.acquire(eq(2L),anyString(),anyString(),eq(run.id),anyLong())).thenReturn(AwsSecurityRepoReviews.Claim.WAITING);
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        assertEquals(AwsSecurityRun.Stage.INPUT_READY,run.stage);verify(gateway,never()).start(any(),anyString(),any());
    }
    @Test void aRejectedStartFailsTheScanAndFreesTheLockForTheNextOne() {
        shared();lockFree("cr-1");
        when(gateway.start(any(),anyString(),any())).thenThrow(ValidationException.builder().message("private").build());
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        assertEquals(AwsSecurityRun.Stage.FAILED,run.stage);verify(repoReviews).release(2L,run.id);
    }
    @Test void anUncertainUpdateKeepsTheLockAndTheRetryFinishesTheJob() {
        shared();lockFree("cr-1");
        doThrow(new IllegalStateException("timeout")).doNothing().when(gateway).updateSource(any(),eq("cr-1"),anyString());
        when(gateway.start(any(),eq("cr-1"),any())).thenReturn("job-5");
        assertTrue(coordinator.run(run.id,()->{},System.currentTimeMillis()+60000));
        assertEquals(AwsSecurityRun.Stage.CREATING,run.stage);assertTrue(run.needsReconciliation);verify(repoReviews,never()).release(anyLong(),anyString());
        run.needsReconciliation=false;
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        assertEquals(AwsSecurityRun.Stage.RUNNING,run.stage);assertEquals("job-5",run.jobId);verify(repoReviews).release(2L,run.id);
    }
    @Test void anUncertainStartIsResolvedByTheJobThatRecordedThisScansSource() {
        shared();run.stage=AwsSecurityRun.Stage.STARTING;run.reviewId="cr-1";run.needsReconciliation=true;run.startAttemptAt=System.currentTimeMillis()-10_000;
        when(gateway.findJobBySource(any(),eq("cr-1"),eq(ownSource()),any())).thenReturn(Optional.of("job-9"));
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        assertEquals(AwsSecurityRun.Stage.RUNNING,run.stage);assertEquals("job-9",run.jobId);assertFalse(run.needsReconciliation);
        verify(gateway,never()).start(any(),anyString(),any());verify(repoReviews).release(2L,run.id);
    }
    @Test void aMissingJobIsNotProofThatTheStartNeverHappenedUntilAGracePeriodHasPassed() {
        shared();run.stage=AwsSecurityRun.Stage.STARTING;run.reviewId="cr-1";run.needsReconciliation=true;run.startAttemptAt=System.currentTimeMillis()-10_000;
        when(gateway.findJobBySource(any(),anyString(),anyString(),any())).thenReturn(Optional.empty());
        assertTrue(coordinator.run(run.id,()->{},System.currentTimeMillis()+60000));
        assertEquals(AwsSecurityRun.Stage.STARTING,run.stage);assertTrue(run.needsReconciliation);
        verify(gateway,never()).start(any(),anyString(),any());verify(repoReviews,never()).release(anyLong(),anyString());
    }
    @Test void afterTheGracePeriodAScanWithNoJobRedoesTheUpdateAndStartUnderTheLock() {
        shared();run.stage=AwsSecurityRun.Stage.STARTING;run.reviewId="cr-1";run.needsReconciliation=true;run.startAttemptAt=System.currentTimeMillis()-10*60_000;
        when(gateway.findJobBySource(any(),anyString(),anyString(),any())).thenReturn(Optional.empty());
        when(repoReviews.acquire(eq(2L),anyString(),anyString(),eq(run.id),anyLong())).thenReturn(AwsSecurityRepoReviews.Claim.WAITING);
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        assertEquals(AwsSecurityRun.Stage.INPUT_READY,run.stage);assertFalse(run.needsReconciliation);
    }
    @Test void preparingAPullRequestScanMarksItForTheSharedReviewAndUploadsItsOwnSourceAndPatch() throws Exception {
        run.stage=AwsSecurityRun.Stage.QUEUED;run.sourceKey=null;run.diffKey=null;run.sharedReview=false;
        var integration=mock(com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity.class);
        var api=mock(com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi.class);
        when(sourceIntegrations.findByLabel(anyString())).thenReturn(integration);when(integration.createApi()).thenReturn(api);
        doAnswer(i->{java.nio.file.Files.writeString(((java.nio.file.Path)i.getArgument(2)).resolve("app.py"),"print(1)\n");return null;})
            .when(api).downloadSource(anyString(),anyString(),any(java.nio.file.Path.class),any());
        when(api.rawDiff(anyString(),anyString(),any(),anyInt())).thenReturn("diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-print(0)\n+print(1)\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        when(importer.writeSourceIndex(anyString(),anyString(),any(),any())).thenReturn("source-index");when(importer.writeDiffIndex(anyString(),any(),any())).thenReturn("diff-index");
        when(inputs.put(any(),anyString(),any(),anyString())).thenReturn("version");
        when(repoReviews.acquire(anyLong(),anyString(),anyString(),anyString(),anyLong())).thenReturn(AwsSecurityRepoReviews.Claim.WAITING); // stop before any AWS call
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        assertTrue(run.sharedReview,"a pull request scan uses the repository's shared review");
        assertTrue(run.sourceKey.contains("/pull_request/"+run.parentId+"/"+run.id+"/"),run.sourceKey);assertTrue(run.diffKey.endsWith("/changes.patch"));
        assertEquals(AwsSecurityRun.Stage.INPUT_READY,run.stage);
    }
    @Test void aRunThatIsNotSharedKeepsItsOwnReviewAndNeverTouchesTheRepositoryLock() {
        when(gateway.create(any(),anyString(),anyString())).thenReturn("own-review");when(gateway.start(any(),eq("own-review"),any())).thenReturn("job-6");
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        assertEquals("own-review",run.reviewId);verify(gateway).create(any(),eq(AwsSecurityIdentity.reviewTitle(run)),anyString());
        verifyNoInteractions(repoReviews);
    }
    @Test void revokedSetupGrantCancelsBeforeAnySourceUploadOrProviderCall()throws Exception{
        run.parentType="setup";run.setupMode=AwsSecuritySetupMode.FULL;run.setupRequester="revoked";run.stage=AwsSecurityRun.Stage.QUEUED;
        coordinator.setSetupAccess(mock(AwsSecuritySetupAccess.class));
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        assertEquals(AwsSecurityRun.Stage.CANCELED,run.stage);verifyNoInteractions(gateway);
        verify(inputs,never()).put(any(),anyString(),any(),anyString());
    }
    @Test void cleanAndDifferentialFixturesStayBoundedAndHaveDistinctReviewedExpectations()throws Exception{
        var directory=java.nio.file.Files.createTempDirectory("synthetic-fixture-test");
        try{
            AwsSecuritySetupFixture.write(directory,AwsSecuritySetupMode.CLEAN);
            String clean=java.nio.file.Files.readString(directory.resolve("app.py"));
            // Nothing a reviewer could flag: no web route, no process, no request input. The earlier clean variant kept an
            // open /diagnostic route returning system information, and AWS reported findings on it on every run.
            assertTrue(clean.contains("def add("));
            assertFalse(clean.contains("subprocess"));assertFalse(clean.contains("flask"));assertFalse(clean.contains("shell=True"));
            assertFalse(clean.contains("request"));
            AwsSecuritySetupFixture.write(directory,AwsSecuritySetupMode.DIFFERENTIAL);
            assertTrue(java.nio.file.Files.readString(directory.resolve("app.py")).contains("shell=True"));
            var patch=AwsSecuritySetupFixture.patch();AwsSecurityInputStore.validatePatch(patch);
            assertTrue(new String(patch,java.nio.charset.StandardCharsets.UTF_8).contains("diff --git a/app.py b/app.py"));
        }finally{org.apache.commons.io.FileUtils.deleteDirectory(directory.toFile());}
    }
    @Test void cancelledUnsubmittedSetupNeedsNoOldProfileToCleanNothing(){
        run.parentType="setup";run.stage=AwsSecurityRun.Stage.CANCELED;run.sourceKey=null;run.diffKey=null;
        coordinator=new AwsSecurityScanCoordinator(persistence,runRepository,gateway,inputs,importer,sourceIntegrations,AwsTestSupport.settings("",""),moduleControls,repositoryPermissions,repoReviews);
        coordinator.run(run.id,()->{},System.currentTimeMillis()+60000);
        assertTrue(run.cleanupComplete);assertEquals(Long.MAX_VALUE,run.dueAt);verifyNoInteractions(gateway,inputs,sourceIntegrations);
    }

}
