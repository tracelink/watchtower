package com.tracelink.appsec.module.awssecurity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.services.securityagent.SecurityAgentClient;
import software.amazon.awssdk.services.securityagent.model.*;

class AwsSecurityGatewayTest {
    @Test void createsOnlyS3InputsWithSimulationAndRemediationDisabled() {
        var reads=mock(SecurityAgentClient.class); var writes=mock(SecurityAgentClient.class); var gateway=new AwsSecurityClientGateway(reads,writes);
        when(writes.createCodeReview(any(CreateCodeReviewRequest.class))).thenReturn(CreateCodeReviewResponse.builder().codeReviewId("review").build());
        assertEquals("review",gateway.create(AwsTestSupport.settings().profile(),"correlation","s3://inputs/run/source.zip"));
        var request=ArgumentCaptor.forClass(CreateCodeReviewRequest.class);verify(writes).createCodeReview(request.capture());
        assertEquals("s3://inputs/run/source.zip",request.getValue().assets().sourceCode().getFirst().s3Location());
        assertTrue(request.getValue().assets().integratedRepositories().isEmpty());
        assertEquals(ValidationMode.DISABLED,request.getValue().validationMode());
        assertEquals("logs", request.getValue().logConfig().logGroup());
        assertEquals(CodeRemediationStrategy.DISABLED,request.getValue().codeRemediationStrategy());verifyNoInteractions(reads);
    }
    @Test void omittedLogGroupUsesProviderDefaultsWithoutAnEmptyLogConfig() {
        var client = mock(SecurityAgentClient.class);
        var settings = AwsTestSupport.settings("", "");
        assertNull(settings.configurationIssue());
        when(client.createCodeReview(any(CreateCodeReviewRequest.class)))
            .thenReturn(CreateCodeReviewResponse.builder().codeReviewId("review").build());
        new AwsSecurityClientGateway(client, client).create(settings.profile(), "correlation", "s3://inputs/source.zip");
        var request = ArgumentCaptor.forClass(CreateCodeReviewRequest.class);
        verify(client).createCodeReview(request.capture());
        assertNull(request.getValue().logConfig());
        assertEquals(settings.serviceRole(), request.getValue().serviceRole());
    }
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void acceptedCreateRecoveryAllowsProviderDefaultLogsOnlyWhenNotOverridden(boolean providerLogs) {
        var client = mock(SecurityAgentClient.class);
        var gateway = new AwsSecurityClientGateway(client, client);
        var profile = AwsTestSupport.settings("", "").profile();
        when(client.listCodeReviews(any(ListCodeReviewsRequest.class))).thenReturn(ListCodeReviewsResponse.builder()
            .codeReviewSummaries(CodeReviewSummary.builder().title("correlation").codeReviewId("review").build()).build());
        var review = CodeReview.builder().codeReviewId("review").agentSpaceId(profile.spaceId()).title("correlation")
            .serviceRole(profile.serviceRole()).assets(Assets.builder()
                .sourceCode(SourceCodeRepository.builder().s3Location("s3://inputs/source.zip").build()).build())
            .validationMode(ValidationMode.DISABLED).codeRemediationStrategy(CodeRemediationStrategy.DISABLED);
        if (providerLogs) review.logConfig(CloudWatchLog.builder().logGroup("aws-default-log-group").build());
        when(client.batchGetCodeReviews(any(BatchGetCodeReviewsRequest.class))).thenReturn(BatchGetCodeReviewsResponse.builder()
            .codeReviews(review.build()).build());
        assertEquals("review", gateway.reconcileCreate(profile, "correlation", "s3://inputs/source.zip").orElseThrow());
        assertTrue(gateway.reconcileCreate(AwsTestSupport.settings().profile(), "correlation", "s3://inputs/source.zip").isEmpty());
        assertTrue(gateway.reconcileCreate(profile, "correlation", "s3://inputs/different.zip").isEmpty());
        verify(client, never()).createCodeReview(any(CreateCodeReviewRequest.class));
    }
    @Test void fullAndDifferentialRequestsUseActualSdkShapes() {
        var client=mock(SecurityAgentClient.class);var gateway=new AwsSecurityClientGateway(client,client);
        when(client.startCodeReviewJob(any(StartCodeReviewJobRequest.class))).thenReturn(StartCodeReviewJobResponse.builder().codeReviewJobId("job").build());
        gateway.start(AwsTestSupport.settings().profile(),"review",null);
        gateway.start(AwsTestSupport.settings().profile(),"review","s3://inputs/changes.diff");
        var request=ArgumentCaptor.forClass(StartCodeReviewJobRequest.class);verify(client,times(2)).startCodeReviewJob(request.capture());
        assertNull(request.getAllValues().get(0).diffSource());assertEquals("s3://inputs/changes.diff",request.getAllValues().get(1).diffSource().s3Uri());
    }
    @Test void correlationTitleAloneCannotRecoverAnAcceptedCreate() {
        var client=mock(SecurityAgentClient.class);var gateway=new AwsSecurityClientGateway(client,client);var p=AwsTestSupport.settings().profile();
        when(client.listCodeReviews(any(ListCodeReviewsRequest.class))).thenReturn(ListCodeReviewsResponse.builder()
            .codeReviewSummaries(CodeReviewSummary.builder().title("correlation").codeReviewId("review").build()).build());
        when(client.batchGetCodeReviews(any(BatchGetCodeReviewsRequest.class))).thenReturn(BatchGetCodeReviewsResponse.builder()
            .codeReviews(CodeReview.builder().codeReviewId("review").agentSpaceId("space").title("correlation").serviceRole(p.serviceRole())
                .assets(Assets.builder().sourceCode(SourceCodeRepository.builder().s3Location("s3://wrong/source.zip").build()).build())
                .validationMode(ValidationMode.DISABLED).codeRemediationStrategy(CodeRemediationStrategy.DISABLED).build()).build());
        assertTrue(gateway.reconcileCreate(p,"correlation","s3://inputs/source.zip").isEmpty());verify(client,never()).createCodeReview(any(CreateCodeReviewRequest.class));
    }
    // ---- the shared per-repository review
    @Test void updatingAReviewSendsTheNewSourceAndEveryRequiredSetting() {
        var client=mock(SecurityAgentClient.class);var gateway=new AwsSecurityClientGateway(client,client);var p=AwsTestSupport.settings().profile();
        gateway.updateSource(p,"review","s3://inputs/scan-2/source.zip");
        var request=ArgumentCaptor.forClass(UpdateCodeReviewRequest.class);verify(client).updateCodeReview(request.capture());
        var sent=request.getValue();
        assertEquals("review",sent.codeReviewId());assertEquals(p.spaceId(),sent.agentSpaceId());
        assertEquals("s3://inputs/scan-2/source.zip",sent.assets().sourceCode().getFirst().s3Location());
        assertEquals(1,sent.assets().sourceCode().size());assertTrue(sent.assets().integratedRepositories().isEmpty());
        // AWS refuses a source update that does not repeat the service role ("Service role is required when source code is provided").
        assertEquals(p.serviceRole(),sent.serviceRole());
        assertEquals(ValidationMode.DISABLED,sent.validationMode());assertEquals(CodeRemediationStrategy.DISABLED,sent.codeRemediationStrategy());
        assertEquals("logs",sent.logConfig().logGroup());
    }
    @Test void aSharedReviewIsFoundByTitleWhateverSourceItPointsAtButOnlyInOurSpaceAndRole() {
        var client=mock(SecurityAgentClient.class);var gateway=new AwsSecurityClientGateway(client,client);var p=AwsTestSupport.settings().profile();
        when(client.listCodeReviews(any(ListCodeReviewsRequest.class))).thenReturn(ListCodeReviewsResponse.builder().codeReviewSummaries(
            CodeReviewSummary.builder().title("repo-title").codeReviewId("mine").build(),
            CodeReviewSummary.builder().title("repo-title").codeReviewId("other-role").build(),
            CodeReviewSummary.builder().title("another").codeReviewId("not-it").build()).build());
        when(client.batchGetCodeReviews(any(BatchGetCodeReviewsRequest.class))).thenAnswer(i->{
            String id=((BatchGetCodeReviewsRequest)i.getArgument(0)).codeReviewIds().getFirst();
            return BatchGetCodeReviewsResponse.builder().codeReviews(CodeReview.builder().codeReviewId(id).agentSpaceId(p.spaceId()).title("repo-title")
                .serviceRole("mine".equals(id)?p.serviceRole():"arn:aws:iam::1:role/other")
                .assets(Assets.builder().sourceCode(SourceCodeRepository.builder().s3Location("s3://inputs/whatever/source.zip").build()).build()).build()).build();
        });
        assertEquals("mine",gateway.findReviewByTitle(p,"repo-title").orElseThrow());
    }
    @Test void twoReviewsWithTheSharedTitleAreNeverChosenBetween() {
        var client=mock(SecurityAgentClient.class);var gateway=new AwsSecurityClientGateway(client,client);var p=AwsTestSupport.settings().profile();
        when(client.listCodeReviews(any(ListCodeReviewsRequest.class))).thenReturn(ListCodeReviewsResponse.builder().codeReviewSummaries(
            CodeReviewSummary.builder().title("repo-title").codeReviewId("a").build(),CodeReviewSummary.builder().title("repo-title").codeReviewId("b").build()).build());
        when(client.batchGetCodeReviews(any(BatchGetCodeReviewsRequest.class))).thenAnswer(i->BatchGetCodeReviewsResponse.builder().codeReviews(
            CodeReview.builder().codeReviewId(((BatchGetCodeReviewsRequest)i.getArgument(0)).codeReviewIds().getFirst()).agentSpaceId(p.spaceId()).title("repo-title")
                .serviceRole(p.serviceRole()).assets(Assets.builder().sourceCode(SourceCodeRepository.builder().s3Location("s3://x/source.zip").build()).build()).build()).build());
        assertTrue(gateway.findReviewByTitle(p,"repo-title").isEmpty());
    }
    @Test void aStartedJobIsFoundByTheSourceItRecordedAmongTheReviewsManyJobs() {
        var client=mock(SecurityAgentClient.class);var gateway=new AwsSecurityClientGateway(client,client);var p=AwsTestSupport.settings().profile();
        var old=java.time.Instant.parse("2026-10-29T06:00:00Z");var recent=java.time.Instant.parse("2026-10-29T07:30:00Z");
        when(client.listCodeReviewJobsForCodeReview(any(ListCodeReviewJobsForCodeReviewRequest.class))).thenReturn(ListCodeReviewJobsForCodeReviewResponse.builder()
            .codeReviewJobSummaries(CodeReviewJobSummary.builder().codeReviewJobId("old-job").createdAt(old).build(),
                CodeReviewJobSummary.builder().codeReviewJobId("ours").createdAt(recent).build(),
                CodeReviewJobSummary.builder().codeReviewJobId("someone-elses").createdAt(recent).build()).build());
        when(client.batchGetCodeReviewJobs(any(BatchGetCodeReviewJobsRequest.class))).thenAnswer(i->{
            var ids=((BatchGetCodeReviewJobsRequest)i.getArgument(0)).codeReviewJobIds();
            return BatchGetCodeReviewJobsResponse.builder().codeReviewJobs(ids.stream().map(id->CodeReviewJob.builder().codeReviewJobId(id).codeReviewId("review")
                .sourceCode(SourceCodeRepository.builder().s3Location("ours".equals(id)?"s3://inputs/scan-2/source.zip":"s3://inputs/other/source.zip").build()).build()).toList()).build();
        });
        assertEquals("ours",gateway.findJobBySource(p,"review","s3://inputs/scan-2/source.zip",java.time.Instant.parse("2026-10-29T07:00:00Z")).orElseThrow());
        assertTrue(gateway.findJobBySource(p,"review","s3://inputs/never-started/source.zip",java.time.Instant.parse("2026-10-29T07:00:00Z")).isEmpty());
        // A job created before the start was attempted cannot be ours, even if it names our source.
        assertTrue(gateway.findJobBySource(p,"review","s3://inputs/other/source.zip",java.time.Instant.parse("2026-10-29T07:45:00Z")).isEmpty());
    }
    @Test void multipleJobsNeverTriggerReplacementOrChooseArbitrarily() {
        var client=mock(SecurityAgentClient.class);var gateway=new AwsSecurityClientGateway(client,client);
        when(client.listCodeReviewJobsForCodeReview(any(ListCodeReviewJobsForCodeReviewRequest.class))).thenReturn(
            ListCodeReviewJobsForCodeReviewResponse.builder().codeReviewJobSummaries(CodeReviewJobSummary.builder().codeReviewJobId("one").build(),CodeReviewJobSummary.builder().codeReviewJobId("two").build()).build());
        assertTrue(gateway.reconcileStart(AwsTestSupport.settings().profile(),"review").isEmpty());verify(client,never()).startCodeReviewJob(any(StartCodeReviewJobRequest.class));
    }
}
