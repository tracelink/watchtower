package com.tracelink.appsec.watchtower.core.scan.queue;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.util.List;
import java.util.concurrent.CompletableFuture;

import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanAgent;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanSubmitResult;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestState;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.ScanExecutionResult;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanningService;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryService;

import software.amazon.awssdk.services.sqs.model.Message;

/**
 * IMPROVEMENT_PLAN.md item 4.5's test requirements. Every test constructs
 * {@link SqsScanConsumer} directly (never via the {@code @Scheduled} loop), matching
 * this codebase's pattern of pausing/avoiding the real executor rather than racing it -
 * see the async-race-test-flakiness lessons applied elsewhere this session.
 */
public class SqsScanConsumerTest {

	private final SqsScanQueueService mockSqsScanQueueService = mock(SqsScanQueueService.class);
	private final PRScanningService mockPRScanningService = mock(PRScanningService.class);
	private final PRScanResultService mockPRScanResultService = mock(PRScanResultService.class);
	private final ApiIntegrationService mockApiService = mock(ApiIntegrationService.class);
	private final RepositoryService mockRepoService = mock(RepositoryService.class);
	private final ScanRegistrationService mockScanRegistrationService =
			mock(ScanRegistrationService.class);

	private SqsScanConsumer newConsumer(boolean sqsSubmissionEnabled, int maxThreads) {
		return new SqsScanConsumer(mockSqsScanQueueService, mockPRScanningService,
				mockPRScanResultService, mockApiService, mockRepoService,
				mockScanRegistrationService, sqsSubmissionEnabled, maxThreads);
	}

	private Message message(String body) {
		return Message.builder().body(body).receiptHandle("receipt-1").build();
	}

	private String messageBody(String apiLabel, String repoName, String prId, String commitHash)
			throws Exception {
		ScanRequestMessage msg = new ScanRequestMessage(apiLabel, repoName, prId, commitHash,
				System.currentTimeMillis());
		return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(msg);
	}

	@Test
	public void testPollNoOpWhenSubmissionDisabled() {
		SqsScanConsumer consumer = newConsumer(false, 4);

		consumer.poll();

		verifyNoInteractions(mockSqsScanQueueService);
	}

	@Test
	public void testPollNoOpWhenSqsNotEnabled() {
		given(mockSqsScanQueueService.isEnabled()).willReturn(false);
		SqsScanConsumer consumer = newConsumer(true, 4);

		consumer.poll();

		verify(mockSqsScanQueueService, never()).poll();
	}

	@Test
	public void testPollNoOpWhenQuiesced() {
		given(mockSqsScanQueueService.isEnabled()).willReturn(true);
		given(mockPRScanningService.isQuiesced()).willReturn(true);
		SqsScanConsumer consumer = newConsumer(true, 4);

		consumer.poll();

		verify(mockSqsScanQueueService, never()).poll();
	}

	@Test
	public void testPollNoOpWhenPaused() {
		given(mockSqsScanQueueService.isEnabled()).willReturn(true);
		given(mockPRScanningService.isPaused()).willReturn(true);
		SqsScanConsumer consumer = newConsumer(true, 4);

		consumer.poll();

		verify(mockSqsScanQueueService, never()).poll();
	}

	@Test
	public void testPollNoOpWhenThreadPoolAtCapacity() {
		given(mockSqsScanQueueService.isEnabled()).willReturn(true);
		given(mockPRScanningService.getTaskNumActive()).willReturn(4L);
		SqsScanConsumer consumer = newConsumer(true, 4);

		consumer.poll();

		verify(mockSqsScanQueueService, never()).poll();
	}

	@Test
	public void testPollDropsARequestForAPausedRepositoryWithoutScanning() throws Exception {
		given(mockSqsScanQueueService.isEnabled()).willReturn(true);
		String body = messageBody("api", "repo", "1", "abc123");
		given(mockSqsScanQueueService.poll()).willReturn(List.of(message(body)));
		RepositoryEntity repo = new RepositoryEntity();
		repo.setRuleset(new RulesetEntity());
		repo.setScanningPaused(true);
		given(mockRepoService.upsertRepo(CodeScanType.PULL_REQUEST, "api", "repo"))
				.willReturn(repo);
		given(mockApiService.findByLabel("api")).willReturn(mock(ApiIntegrationEntity.class));

		newConsumer(true, 4).poll();

		verify(mockSqsScanQueueService).markCompleted(any());
		verify(mockSqsScanQueueService).delete("receipt-1");
		verify(mockPRScanningService, never()).executeScan(any(), any(), any(), any(),
				org.mockito.ArgumentMatchers.anyLong());
	}

	@Test
	public void testPollProcessesMessageAndDeletesOnSuccess() throws Exception {
		given(mockSqsScanQueueService.isEnabled()).willReturn(true);
		String body = messageBody("api", "repo", "1", "abc123");
		given(mockSqsScanQueueService.poll()).willReturn(List.of(message(body)));

		RepositoryEntity repo = new RepositoryEntity();
		RulesetEntity ruleset = new RulesetEntity();
		repo.setRuleset(ruleset);
		given(mockRepoService.upsertRepo(CodeScanType.PULL_REQUEST, "api", "repo"))
				.willReturn(repo);
		given(mockScanRegistrationService.hasCodeScanners()).willReturn(true);

		ApiIntegrationEntity apiEntity = mock(ApiIntegrationEntity.class);
		IScmApi mockApi = mock(IScmApi.class);
		given(apiEntity.createApi()).willReturn(mockApi);
		given(mockApiService.findByLabel("api")).willReturn(apiEntity);

		PullRequest active = mock(PullRequest.class);
		given(active.getState()).willReturn(PullRequestState.ACTIVE);
		given(active.getPRString()).willReturn("repo-1");
		given(mockApi.updatePRData(any())).willReturn(active);
		PRScanAgent mockAgent = mock(PRScanAgent.class);
		given(mockAgent.hasFailed()).willReturn(false);
		given(mockPRScanningService.executeScan(eq(active), eq(mockApi), eq(ruleset),
				eq("receipt-1"), org.mockito.ArgumentMatchers.anyLong()))
				.willReturn(new ScanExecutionResult(PRScanSubmitResult.QUEUED, mockAgent,
						CompletableFuture.completedFuture(null)));

		SqsScanConsumer consumer = newConsumer(true, 4);
		consumer.poll();

		verify(mockPRScanningService).executeScan(eq(active), eq(mockApi), eq(ruleset),
				eq("receipt-1"), org.mockito.ArgumentMatchers.anyLong());
		verify(mockSqsScanQueueService).requeue("receipt-1", 300);
		verify(mockSqsScanQueueService).delete("receipt-1");
		verify(mockPRScanResultService, never()).markPrResolved(any(), anyBoolean());
	}

	@Test
	public void testPollLeavesMessageWhenAgentFailsAsynchronously() throws Exception {
		// IMPROVEMENT_PLAN.md item 4.7's prerequisite fix: the CompletableFuture wrapping
		// an agent's run() always completes normally (run() never lets an exception
		// escape), so deletion must be gated on agent.hasFailed(), not on the future's
		// completion alone - the exact bug where an async failure (unrelated to rate
		// limiting) used to have its message deleted as if it had succeeded.
		given(mockSqsScanQueueService.isEnabled()).willReturn(true);
		String body = messageBody("api", "repo", "1", "abc123");
		given(mockSqsScanQueueService.poll()).willReturn(List.of(message(body)));

		RepositoryEntity repo = new RepositoryEntity();
		RulesetEntity ruleset = new RulesetEntity();
		repo.setRuleset(ruleset);
		given(mockRepoService.upsertRepo(CodeScanType.PULL_REQUEST, "api", "repo"))
				.willReturn(repo);
		given(mockScanRegistrationService.hasCodeScanners()).willReturn(true);

		ApiIntegrationEntity apiEntity = mock(ApiIntegrationEntity.class);
		IScmApi mockApi = mock(IScmApi.class);
		given(apiEntity.createApi()).willReturn(mockApi);
		given(mockApiService.findByLabel("api")).willReturn(apiEntity);

		PullRequest active = mock(PullRequest.class);
		given(active.getState()).willReturn(PullRequestState.ACTIVE);
		given(mockApi.updatePRData(any())).willReturn(active);
		PRScanAgent mockAgent = mock(PRScanAgent.class);
		given(mockAgent.hasFailed()).willReturn(true);
		given(mockPRScanningService.executeScan(eq(active), eq(mockApi), eq(ruleset),
				eq("receipt-1"), org.mockito.ArgumentMatchers.anyLong()))
				.willReturn(new ScanExecutionResult(PRScanSubmitResult.QUEUED, mockAgent,
						CompletableFuture.completedFuture(null)));

		SqsScanConsumer consumer = newConsumer(true, 4);
		consumer.poll();

		verify(mockSqsScanQueueService, never()).delete(anyString());
	}

	@Test
	public void testPollDeletesMessageImmediatelyWhenScanIsDeduplicated() throws Exception {
		given(mockSqsScanQueueService.isEnabled()).willReturn(true);
		String body = messageBody("api", "repo", "1", "abc123");
		given(mockSqsScanQueueService.poll()).willReturn(List.of(message(body)));

		RepositoryEntity repo = new RepositoryEntity();
		RulesetEntity ruleset = new RulesetEntity();
		repo.setRuleset(ruleset);
		given(mockRepoService.upsertRepo(CodeScanType.PULL_REQUEST, "api", "repo"))
				.willReturn(repo);
		given(mockScanRegistrationService.hasCodeScanners()).willReturn(true);

		ApiIntegrationEntity apiEntity = mock(ApiIntegrationEntity.class);
		IScmApi mockApi = mock(IScmApi.class);
		given(apiEntity.createApi()).willReturn(mockApi);
		given(mockApiService.findByLabel("api")).willReturn(apiEntity);

		PullRequest active = mock(PullRequest.class);
		given(active.getState()).willReturn(PullRequestState.ACTIVE);
		given(mockApi.updatePRData(any())).willReturn(active);
		given(mockPRScanningService.executeScan(eq(active), eq(mockApi), eq(ruleset),
				eq("receipt-1"), org.mockito.ArgumentMatchers.anyLong()))
				.willReturn(new ScanExecutionResult(PRScanSubmitResult.DEDUPLICATED, null, null));

		SqsScanConsumer consumer = newConsumer(true, 4);
		consumer.poll();

		// No future to wait on - another execution already owns the outcome - so this
		// message is done immediately rather than left to redeliver forever.
		verify(mockSqsScanQueueService).delete("receipt-1");
	}

	@Test
	public void testPollLeavesMessageInQueueWhenExecuteScanThrows() throws Exception {
		given(mockSqsScanQueueService.isEnabled()).willReturn(true);
		String body = messageBody("api", "repo", "1", "abc123");
		given(mockSqsScanQueueService.poll()).willReturn(List.of(message(body)));
		RepositoryEntity repo = new RepositoryEntity();
		repo.setRuleset(new RulesetEntity());
		given(mockRepoService.upsertRepo(CodeScanType.PULL_REQUEST, "api", "repo"))
				.willReturn(repo);
		given(mockScanRegistrationService.hasCodeScanners()).willReturn(true);
		ApiIntegrationEntity apiEntity = mock(ApiIntegrationEntity.class);
		IScmApi mockApi = mock(IScmApi.class);
		given(apiEntity.createApi()).willReturn(mockApi);
		given(mockApiService.findByLabel("api")).willReturn(apiEntity);
		given(mockApi.updatePRData(any())).willThrow(new IllegalStateException("SCM unavailable"));

		SqsScanConsumer consumer = newConsumer(true, 4);
		consumer.poll();

		// A transient SCM failure is retried. It must not become a validation failure.
		verify(mockSqsScanQueueService, never()).delete(anyString());
		verify(mockSqsScanQueueService).markQueued(any(ScanRequestMessage.class));
		verify(mockSqsScanQueueService, never()).markValidationFailed(
				any(ScanRequestMessage.class), anyString());
	}

	@Test
	public void testPollDropsARequestForAPullRequestTheProviderDoesNotKnow() throws Exception {
		given(mockSqsScanQueueService.isEnabled()).willReturn(true);
		String body = messageBody("api", "repo", "999999", "abc123");
		given(mockSqsScanQueueService.poll()).willReturn(List.of(message(body)));
		RepositoryEntity repo = new RepositoryEntity();
		repo.setRuleset(new RulesetEntity());
		given(mockRepoService.upsertRepo(CodeScanType.PULL_REQUEST, "api", "repo"))
				.willReturn(repo);
		given(mockScanRegistrationService.hasCodeScanners()).willReturn(true);
		ApiIntegrationEntity apiEntity = mock(ApiIntegrationEntity.class);
		IScmApi mockApi = mock(IScmApi.class);
		given(apiEntity.createApi()).willReturn(mockApi);
		given(mockApiService.findByLabel("api")).willReturn(apiEntity);
		given(mockApi.updatePRData(any())).willThrow(
				new com.tracelink.appsec.watchtower.core.exception.PullRequestNotFoundException(
						"Pull request not found"));

		newConsumer(true, 4).poll();

		// Permanent: redelivering it every few minutes could never make the pull request exist
		verify(mockSqsScanQueueService).markValidationFailed(any(ScanRequestMessage.class),
				eq("Pull request not found"));
		verify(mockSqsScanQueueService).delete("receipt-1");
		verify(mockSqsScanQueueService, never()).markQueued(any(ScanRequestMessage.class));
	}

	@Test
	public void testPollDeletesUnreadableMessage() {
		given(mockSqsScanQueueService.isEnabled()).willReturn(true);
		given(mockSqsScanQueueService.poll()).willReturn(List.of(message("not valid json")));

		SqsScanConsumer consumer = newConsumer(true, 4);
		consumer.poll();

		verify(mockSqsScanQueueService).delete("receipt-1");
		verifyNoInteractions(mockApiService);
	}

	@Test
	public void testPollDropsMessageWhenRulesetMissing() throws Exception {
		given(mockSqsScanQueueService.isEnabled()).willReturn(true);
		String body = messageBody("api", "repo", "1", "abc123");
		given(mockSqsScanQueueService.poll()).willReturn(List.of(message(body)));

		RepositoryEntity repo = new RepositoryEntity();
		// No ruleset set.
		given(mockRepoService.upsertRepo(CodeScanType.PULL_REQUEST, "api", "repo"))
				.willReturn(repo);
		ApiIntegrationEntity apiEntity = mock(ApiIntegrationEntity.class);
		given(mockApiService.findByLabel("api")).willReturn(apiEntity);

		SqsScanConsumer consumer = newConsumer(true, 4);
		consumer.poll();

		verify(mockPRScanningService, never()).executeScan(any(), any(), any(), any(),
				org.mockito.ArgumentMatchers.anyLong());
		// A repository that will never scan (no ruleset) is a permanent, not transient,
		// condition, so the message is dropped rather than redelivered forever.
		verify(mockSqsScanQueueService).delete("receipt-1");
		verify(mockSqsScanQueueService).markValidationFailed(any(),
				eq("Repository has no configured ruleset"));
	}

	@Test
	public void testPollRecordsUnknownConnectionAsValidationFailure() throws Exception {
		given(mockSqsScanQueueService.isEnabled()).willReturn(true);
		String body = messageBody("missing", "repo", "1", "abc123");
		given(mockSqsScanQueueService.poll()).willReturn(List.of(message(body)));
		given(mockApiService.findByLabel("missing")).willReturn(null);

		newConsumer(true, 4).poll();

		verify(mockSqsScanQueueService).markValidationFailed(any(),
				eq("Connection is no longer configured"));
		verify(mockSqsScanQueueService).delete("receipt-1");
	}

	@Test
	public void testPollMarksResolvedForClosedPullRequestWithoutScanning() throws Exception {
		given(mockSqsScanQueueService.isEnabled()).willReturn(true);
		String body = messageBody("api", "repo", "1", "abc123");
		given(mockSqsScanQueueService.poll()).willReturn(List.of(message(body)));

		RepositoryEntity repo = new RepositoryEntity();
		RulesetEntity ruleset = new RulesetEntity();
		repo.setRuleset(ruleset);
		given(mockRepoService.upsertRepo(CodeScanType.PULL_REQUEST, "api", "repo"))
				.willReturn(repo);
		given(mockScanRegistrationService.hasCodeScanners()).willReturn(true);

		ApiIntegrationEntity apiEntity = mock(ApiIntegrationEntity.class);
		IScmApi mockApi = mock(IScmApi.class);
		given(apiEntity.createApi()).willReturn(mockApi);
		given(mockApiService.findByLabel("api")).willReturn(apiEntity);

		PullRequest merged = mock(PullRequest.class);
		given(merged.getState()).willReturn(PullRequestState.MERGED);
		given(mockApi.updatePRData(any())).willReturn(merged);

		SqsScanConsumer consumer = newConsumer(true, 4);
		consumer.poll();

		// the request being dropped was a scan pending at the merge
		verify(mockPRScanResultService).markPrResolved(merged, true);
		verify(mockPRScanningService, never()).executeScan(any(), any(), any(), any(),
				org.mockito.ArgumentMatchers.anyLong());
		verify(mockSqsScanQueueService).delete("receipt-1");
	}

	@Test
	public void testPollRecordsUnknownApiLabelAndAcknowledgesMessage() throws Exception {
		given(mockSqsScanQueueService.isEnabled()).willReturn(true);
		String body = messageBody("unknown-api", "repo", "1", "abc123");
		given(mockSqsScanQueueService.poll()).willReturn(List.of(message(body)));
		given(mockApiService.findByLabel("unknown-api")).willReturn(null);

		SqsScanConsumer consumer = newConsumer(true, 4);
		consumer.poll();

		verify(mockSqsScanQueueService).markValidationFailed(any(ScanRequestMessage.class),
				org.mockito.ArgumentMatchers.eq("Connection is no longer configured"));
		verify(mockSqsScanQueueService).delete("receipt-1");
	}
}
