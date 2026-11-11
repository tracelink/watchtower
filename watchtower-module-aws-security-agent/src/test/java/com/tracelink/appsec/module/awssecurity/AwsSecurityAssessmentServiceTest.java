package com.tracelink.appsec.module.awssecurity;

import java.util.Optional;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AwsSecurityAssessmentServiceTest {
    private final AwsSecurityRunRepository runs = mock(AwsSecurityRunRepository.class);
    private final AwsSecurityAssessmentService service = new AwsSecurityAssessmentService(
        AwsTestSupport.settings(), null, null, runs, null, null, null, null, null);

    @Test void aPullRequestsShortCommitsAreCompletedBeforeTheMergeBaseIsAskedFor() throws Exception {
        var api = mock(com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi.class);
        var pr = new com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest("BitBucket");
        pr.setRepoName("wt-test"); pr.setCommitHash("84fbc87ae343"); pr.setBaseCommitHash("1a2b3c4d5e6f");
        String head = "84fbc87ae343" + "0".repeat(28), base = "1a2b3c4d5e6f" + "1".repeat(28), mergeBase = "9".repeat(40);
        when(api.fullCommit("wt-test", "84fbc87ae343")).thenReturn(head);
        when(api.fullCommit("wt-test", "1a2b3c4d5e6f")).thenReturn(base);
        when(api.mergeBase("wt-test", head, base)).thenReturn(mergeBase);

        var pinned = AwsSecurityAssessmentService.pin(api, pr);

        assertEquals(new AwsSecurityAssessmentService.PinnedRefs(head, base, mergeBase), pinned);
    }

    @Test void aCommitThatCannotBeCompletedStopsThePinningInsteadOfAskingWithAShortOne() throws Exception {
        var api = mock(com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi.class);
        var pr = new com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest("BitBucket");
        pr.setRepoName("wt-test"); pr.setCommitHash("84fbc87ae343"); pr.setBaseCommitHash("1a2b3c4d5e6f");
        when(api.fullCommit("wt-test", "84fbc87ae343")).thenThrow(new java.io.IOException("Pinned SCM input unavailable: HTTP 404"));

        assertThrows(java.io.IOException.class, () -> AwsSecurityAssessmentService.pin(api, pr));
        verify(api, never()).mergeBase(any(), any(), any());
    }

    @Test void theLoggedCauseOfAMissingMergeBaseSaysWhereItFailedAndWhy() {
        var pr = new com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest("BitBucket");
        pr.setRepoName("wt-test"); pr.setPrId("59");
        pr.setCommitHash("84fbc87ae343c1d0f4a6b7c8d9e0f1a2b3c4d5e6"); pr.setBaseCommitHash(null);

        String line = AwsSecurityAssessmentService.mergeBaseFailure(pr, new IllegalStateException("no integration is labelled 'BitBucket'"));

        assertEquals("AWS review not submitted for pull request #59 of 'wt-test' on integration 'BitBucket' (head 84fbc87ae343, base none): "
            + "IllegalStateException: no integration is labelled 'BitBucket'", line);
    }

    @Test void aLongOrMultiLineCauseIsKeptToOneBoundedLineAndAMissingMessageIsSaid() {
        var pr = new com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest("BitBucket");
        pr.setRepoName("wt-test"); pr.setPrId("59");

        String multiLine = AwsSecurityAssessmentService.mergeBaseFailure(pr, new RuntimeException("first line\n  second   line\r\n" + "x".repeat(500)));
        String silent = AwsSecurityAssessmentService.mergeBaseFailure(pr, new RuntimeException((String) null));

        assertFalse(multiLine.contains("\n") || multiLine.contains("\r"));
        assertTrue(multiLine.contains("RuntimeException: first line second line xxx"));
        assertTrue(multiLine.endsWith("…"), "a cause longer than the limit is cut");
        assertTrue(multiLine.length() < 520);
        assertTrue(silent.endsWith("RuntimeException: no message"));
        assertTrue(silent.contains("head none, base none"));
    }

    @Test void anActiveAwsReviewDoesNotProduceARepositoryAdmissionBanner() {
        var run = AwsTestSupport.run(); run.parentType = "repository"; run.parentId = 10;
        run.stage = AwsSecurityRun.Stage.CREATING; run.providerTerminal = false;
        run.reviewId = null; run.jobId = null; run.needsReconciliation = true;
        run.statusReason = "AWS operation unavailable (ValidationException); inspect stage and reconcile";
        when(runs.findById(run.id)).thenReturn(Optional.of(run));
        assertTrue(service.repositoryAdmissionBlocker().isEmpty());
        run.providerTerminal = true;
        assertTrue(service.repositoryAdmissionBlocker().isEmpty());
    }
}
