package com.tracelink.appsec.module.awssecurity;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

class AwsSecurityIdentityTest {
    @Test void namesAndUploadFoldersIdentifyTheRepositoryAndScanWithoutReusingAnExecution() {
        var run=AwsTestSupport.run();run.sourceKey=null;
        String title=AwsSecurityIdentity.reviewTitle(run),prefix=AwsSecurityIdentity.inputPrefix(run);
        assertEquals("repo-bb-pr-1-scan-1-"+run.id,title);assertTrue(title.matches("[A-Za-z0-9_-]{1,100}"));
        // <installation>/<integration>/<repository>/<scan type>/<scan id>/<execution>/: browsable by repository and scan, and
        // always inside the prefix the Agent Space is connected to.
        String installation=AwsSecuritySnapshot.decode(run.snapshotJson).profile().installation();
        assertEquals("aws-security-inputs/"+installation+"/bb/repo-r2/pull_request/1/"+run.id+"/1/",prefix);
        var other=AwsTestSupport.run();other.sourceKey=null;assertNotEquals(prefix,AwsSecurityIdentity.inputPrefix(other));
        assertTrue((prefix+AwsSecurityScanCoordinator.DIFF_OBJECT).length()<=255);
    }
    @Test void scansOfTheSameRepositoryNeverShareAnUploadFolderAndAnIntegrationNameCannotAddPathLevels() {
        var first=AwsTestSupport.run();first.sourceKey=null;var second=AwsTestSupport.run();second.sourceKey=null;second.parentId=2;
        var repo=AwsTestSupport.run();repo.sourceKey=null;repo.parentType="repository";
        var prefixes=new java.util.HashSet<>(java.util.List.of(AwsSecurityIdentity.inputPrefix(first),AwsSecurityIdentity.inputPrefix(second),AwsSecurityIdentity.inputPrefix(repo)));
        assertEquals(3,prefixes.size());
        assertTrue(AwsSecurityIdentity.inputPrefix(second).contains("/pull_request/2/"));assertTrue(AwsSecurityIdentity.inputPrefix(repo).contains("/repository/1/"));
        var snapshot=AwsSecuritySnapshot.decode(first.snapshotJson);var c=snapshot.context();
        var context=new com.tracelink.appsec.watchtower.core.scan.code.ScanExecutionContext(c.executionId(),c.type(),c.scanId(),c.repositoryId(),
            "Other Integration/../x","repo",c.branch(),c.commit(),c.pullRequestId(),c.targetBranch(),c.baseCommit(),c.mergeBase());
        first.snapshotJson=new AwsSecuritySnapshot(context,snapshot.profile(),snapshot.rule(),snapshot.ruleName(),snapshot.blockingLevel(),snapshot.policyRevision()).encode();
        String prefix=AwsSecurityIdentity.inputPrefix(first);
        assertTrue(prefix.contains("/Other-Integration-..-x/repo-r2/"),prefix);assertFalse(prefix.contains(" "));
    }
    @Test void providerTitleSanitizesNamesAndBoundsTheWholeTitleWhileKeepingTheExecutionId() {
        var run=AwsTestSupport.run();var snapshot=AwsSecuritySnapshot.decode(run.snapshotJson);var c=snapshot.context();
        var context=new com.tracelink.appsec.watchtower.core.scan.code.ScanExecutionContext(c.executionId(),c.type(),c.scanId(),c.repositoryId(),
            "Integration / "+"x".repeat(100),"org/repo.with spaces-💻-"+"y".repeat(100),c.branch(),c.commit(),c.pullRequestId(),c.targetBranch(),c.baseCommit(),c.mergeBase());
        run.snapshotJson=new AwsSecuritySnapshot(context,snapshot.profile(),snapshot.rule(),snapshot.ruleName(),snapshot.blockingLevel(),snapshot.policyRevision()).encode();
        String title=AwsSecurityIdentity.reviewTitle(run);
        assertTrue(title.matches("[A-Za-z0-9_-]{1,100}"));assertTrue(title.endsWith("pr-1-scan-1-"+run.id));
        run.parentType="setup";run.setupMode=AwsSecuritySetupMode.DIFFERENTIAL;
        assertTrue(AwsSecurityIdentity.reviewTitle(run).matches("[A-Za-z0-9_-]{1,100}"));
        run.parentType="repository";run.parentId=Long.MAX_VALUE;
        assertTrue(AwsSecurityIdentity.reviewTitle(run).matches("[A-Za-z0-9_-]{1,100}"));
        assertTrue(AwsSecurityIdentity.reviewTitle(run).endsWith("scan-"+Long.MAX_VALUE+"-"+run.id));
    }
    // So a person looking at a failed review can find the uploaded inputs (or check CloudTrail for them) without reading code.
    @Test void theReceiptNamesTheS3SourceAndPatchAndSaysWhetherTheyWereRemoved() {
        var run=AwsTestSupport.run();var bucket=AwsSecuritySnapshot.decode(run.snapshotJson).profile().bucket();
        run.sourceKey="aws-security-inputs/test/a/1/source.zip";run.diffKey="aws-security-inputs/test/a/1/changes.patch";run.cleanupComplete=false;
        var facts=run.reference().status().receiptFacts();
        assertEquals("s3://"+bucket+"/aws-security-inputs/test/a/1/source.zip",facts.get("Source in S3"));
        assertEquals("s3://"+bucket+"/aws-security-inputs/test/a/1/changes.patch",facts.get("Patch in S3"));
        assertEquals("No",facts.get("S3 inputs removed"));
        run.cleanupComplete=true;
        assertEquals("Yes",run.reference().status().receiptFacts().get("S3 inputs removed"));
        run.sourceKey=null;run.diffKey=null;
        var none=run.reference().status().receiptFacts();
        assertEquals("Not uploaded",none.get("Source in S3"));assertEquals("Not applicable or not uploaded",none.get("Patch in S3"));
    }
    @Test void theRepositoryReviewTitleIsTheSameForEveryScanOfTheRepositoryAndAlwaysEndsWithItsId() {
        var one=AwsTestSupport.run();var other=AwsTestSupport.run();other.parentId=99;other.parentType="repository";
        assertEquals(AwsSecurityIdentity.repositoryReviewTitle(one),AwsSecurityIdentity.repositoryReviewTitle(other));
        String title=AwsSecurityIdentity.repositoryReviewTitle(one);
        assertEquals("watchtower-bb-repo-r2",title);assertTrue(title.matches("[A-Za-z0-9_-]{1,100}"));
        var snapshot=AwsSecuritySnapshot.decode(one.snapshotJson);var c=snapshot.context();
        var context=new com.tracelink.appsec.watchtower.core.scan.code.ScanExecutionContext(c.executionId(),c.type(),c.scanId(),c.repositoryId(),
            "Integration / "+"x".repeat(100),"org/repo.with spaces-💻-"+"y".repeat(100),c.branch(),c.commit(),c.pullRequestId(),c.targetBranch(),c.baseCommit(),c.mergeBase());
        one.snapshotJson=new AwsSecuritySnapshot(context,snapshot.profile(),snapshot.rule(),snapshot.ruleName(),snapshot.blockingLevel(),snapshot.policyRevision()).encode();
        one.repositoryId=123456789L;
        String long_=AwsSecurityIdentity.repositoryReviewTitle(one);
        assertTrue(long_.matches("[A-Za-z0-9_-]{1,100}"),long_);assertTrue(long_.endsWith("-r123456789"),long_);
    }
    @Test void aSharedReviewIsNeverOfferedForDeletionAndSaysWhoSharesIt() {
        var run=AwsTestSupport.run();run.stage=AwsSecurityRun.Stage.COMPLETE;run.cleanupComplete=true;run.providerTerminal=true;run.needsReconciliation=false;
        assertEquals("true",run.reference().status().receiptFacts().get("Can delete AWS review"));
        assertNull(run.reference().status().receiptFacts().get("AWS review shared"));
        run.sharedReview=true;
        var facts=run.reference().status().receiptFacts();
        assertEquals("false",facts.get("Can delete AWS review"));assertEquals("Yes: one review per repository, one job per scan",facts.get("AWS review shared"));
    }
    @Test void recoveryKeepsPreviouslyPreparedUploadPaths() {
        var run=AwsTestSupport.run();run.sourceKey="aws-security-inputs/test/older-run/1/source.zip";
        assertEquals("aws-security-inputs/test/older-run/1/",AwsSecurityIdentity.inputPrefix(run));
    }
    @Test void portalLinkUsesTheProvidedReviewRouteAndCannotEscapeItsOrigin() {
        String origin="https://app-00000000-0000-0000-0000-000000000000.securityagent.global.app.aws";
        assertEquals(origin+"/as-be0dc657-5cdf-4de5-81c5-de3b5ea50ea4/code-reviews/cr-4a372b4b-9809-4210-9873-11bc986186e1",AwsSecurityEvidencePolicy.reviewUrl(origin,"as-be0dc657-5cdf-4de5-81c5-de3b5ea50ea4","cr-4a372b4b-9809-4210-9873-11bc986186e1"));
        assertNull(AwsSecurityEvidencePolicy.reviewUrl(origin,"../other","review"));assertNull(AwsSecurityEvidencePolicy.reviewUrl(origin,"space","review?token=bad"));assertNull(AwsSecurityEvidencePolicy.reviewUrl("","space","review"));
    }
    @Test void theReceiptRecordsWhenTheReviewWasQueuedAndWhenAwsEndedSoTheReportCanShowTheRealTime() {
        var run=AwsTestSupport.run();run.createdAt=java.time.Instant.parse("2026-10-29T09:00:00Z").toEpochMilli();run.terminalAt=0;run.providerTerminal=false;run.stage=AwsSecurityRun.Stage.RUNNING;
        var running=run.reference().status();
        assertEquals("2026-10-29T09:00:00Z",running.receiptFacts().get("Started"));
        assertNull(running.receiptFacts().get("Finished"),"a running review has no end yet");
        run.terminalAt=run.createdAt+588_000L;run.providerTerminal=true;run.stage=AwsSecurityRun.Stage.IMPORTING;
        var ended=run.reference().status();
        assertEquals("2026-10-29T09:09:48Z",ended.receiptFacts().get("Finished"),"the end counts as soon as the job ended, before the import finishes");
        assertEquals(588_000L,ended.finishedAt()-ended.startedAt());
    }
}
