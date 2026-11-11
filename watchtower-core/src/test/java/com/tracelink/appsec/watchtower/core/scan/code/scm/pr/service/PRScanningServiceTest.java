package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.core.task.TaskRejectedException;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.logging.CoreLogWatchExtension;
import com.tracelink.appsec.watchtower.core.logging.LogsService;
import com.tracelink.appsec.watchtower.core.mock.MockRuleEntity;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.threadpool.PauseableThreadPoolTaskExecutor;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanSubmitResult;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.ManualPullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.ScanExecutionResult;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestState;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.queue.ScanRequestMessage;
import com.tracelink.appsec.watchtower.core.scan.queue.SqsScanQueueService;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryService;
import com.tracelink.appsec.watchtower.core.scan.storage.S3Service;

import ch.qos.logback.classic.Level;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

@ExtendWith({SpringExtension.class, MockitoExtension.class})
@MockitoSettings(strictness = Strictness.LENIENT)
public class PRScanningServiceTest {
	@RegisterExtension
	public CoreLogWatchExtension logWatcher =
			CoreLogWatchExtension.forClass(PRScanningService.class);


	@MockitoBean
	private LogsService mockLogsService;

	@MockitoBean
	private RepositoryService mockRepoService;

	@MockitoBean
	private PRScanResultService mockScanResultService;

	@MockitoBean
	private ScanRegistrationService mockScanRegistrationService;

	@MockitoBean
	private ApiIntegrationService mockApiService;

	@Mock
	private PullRequest mockPR;

	@MockitoBean
	private SqsScanQueueService mockSqsScanQueueService;

	@MockitoBean
	private PullRequestSyncSettingsService mockPrSettingsService;

	private PRScanningService scanningService;
	private SimpleMeterRegistry meterRegistry;

	@BeforeEach
	public void setup() {
		var compatible = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(compatible.getScanType()).thenReturn(CodeScanType.PULL_REQUEST);
		BDDMockito.when(mockApiService.findByLabel(BDDMockito.any())).thenReturn(compatible);
		BDDMockito.when(mockLogsService.getLogsLevel()).thenReturn(Level.INFO);
		this.meterRegistry = new SimpleMeterRegistry();
		this.scanningService =
				new PRScanningService(mockLogsService, mockRepoService,
						mockScanResultService, mockScanRegistrationService, mockApiService,
						meterRegistry, new S3Service("", "us-east-1"), mockSqsScanQueueService,
						mockPrSettingsService, 2,
						false, PauseableThreadPoolTaskExecutor.DEFAULT_QUEUE_CAPACITY, false);
	}

 @Test void imageIntegrationCannotEnqueueOrCreateRepository() {
  var image = new com.tracelink.appsec.watchtower.core.scan.image.api.ecr.EcrIntegrationEntity();
  BDDMockito.when(mockApiService.findByLabel(BDDMockito.any())).thenReturn(image);
  Assertions.assertThrows(ScanRejectedException.class, () -> newScanningServiceWithSqsSubmissionEnabled().doPullRequestScan(mockPR));
  BDDMockito.verifyNoInteractions(mockRepoService, mockSqsScanQueueService);
 }

	private PRScanningService newScanningServiceWithSqsSubmissionEnabled() {
		return new PRScanningService(mockLogsService, mockRepoService,
				mockScanResultService, mockScanRegistrationService, mockApiService,
				meterRegistry, new S3Service("", "us-east-1"), mockSqsScanQueueService,
				mockPrSettingsService, 2,
				false, PauseableThreadPoolTaskExecutor.DEFAULT_QUEUE_CAPACITY, true);
	}

	@Test
	public void testDoPullRequestScan() throws Exception {
		setupDefaultMocks();

		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockApi.updatePRData(BDDMockito.any())).thenAnswer(e -> e.getArgument(0));
		// Test that scan runs as expected
		BDDMockito.when(mockScanRegistrationService.hasCodeScanners()).thenReturn(true);
		BDDMockito.when(mockScanRegistrationService.getCodeScanners())
				.thenReturn(Collections.singleton(new MockScanner()));
		ApiIntegrationEntity mockEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(mockEntity.getScanType()).thenReturn(CodeScanType.PULL_REQUEST);
		BDDMockito.when(mockEntity.createApi()).thenReturn(mockApi);
		BDDMockito.when(mockApiService.findByLabel(BDDMockito.any())).thenReturn(mockEntity);
		scanningService.doPullRequestScan(mockPR);
		// ran without exceptions is expected
	}

	@Test
	public void aScanQueuedOnAnyPodIsPendingAndALookupFailureIsNot() {
		PullRequest pr = new PullRequest("bb");
		pr.setRepoName("payments-api");
		pr.setPrId("7");
		BDDMockito.when(mockSqsScanQueueService.hasPendingScan("bb", "payments-api", "7"))
				.thenReturn(true);
		Assertions.assertTrue(scanningService.hasPendingScan(pr));

		BDDMockito.when(mockSqsScanQueueService.hasPendingScan("bb", "payments-api", "7"))
				.thenThrow(new IllegalStateException("database unavailable"));
		Assertions.assertFalse(scanningService.hasPendingScan(pr),
				"a failed lookup must not stop the pull request being resolved");
	}

	@Test
	public void testDoPullRequestScanSkipsMergedPullRequest() throws Exception {
		// A closed Pull Request must not be scanned. Commenting on it is noise, and
		// blocking it fails outright - Bitbucket answers 400 to a decline on a merged
		// PR. The check has to live here rather than in a controller, because the manual
		// submit path and downtime recovery both reach this method directly.
		setupDefaultMocks();
		BDDMockito.when(mockScanRegistrationService.hasCodeScanners()).thenReturn(true);

		PullRequest merged = BDDMockito.mock(PullRequest.class);
		BDDMockito.when(merged.getState()).thenReturn(PullRequestState.MERGED);

		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockApi.updatePRData(BDDMockito.any())).thenReturn(merged);
		ApiIntegrationEntity mockEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(mockEntity.getScanType()).thenReturn(CodeScanType.PULL_REQUEST);
		BDDMockito.when(mockEntity.createApi()).thenReturn(mockApi);
		BDDMockito.when(mockApiService.findByLabel(BDDMockito.any())).thenReturn(mockEntity);

		scanningService.doPullRequestScan(mockPR);

		BDDMockito.verify(mockScanResultService).markPrResolved(merged, false);
		// No scan agent was built, so nothing was queued.
		BDDMockito.verify(mockScanRegistrationService, BDDMockito.never()).getCodeScanners();
	}

	@Test
	public void testDoPullRequestScanRunsForActivePullRequest() throws Exception {
		setupDefaultMocks();
		BDDMockito.when(mockScanRegistrationService.hasCodeScanners()).thenReturn(true);
		BDDMockito.when(mockScanRegistrationService.getCodeScanners())
				.thenReturn(Collections.singleton(new MockScanner()));

		PullRequest active = BDDMockito.mock(PullRequest.class);
		BDDMockito.when(active.getState()).thenReturn(PullRequestState.ACTIVE);

		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockApi.updatePRData(BDDMockito.any())).thenReturn(active);
		ApiIntegrationEntity mockEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(mockEntity.getScanType()).thenReturn(CodeScanType.PULL_REQUEST);
		BDDMockito.when(mockEntity.createApi()).thenReturn(mockApi);
		BDDMockito.when(mockApiService.findByLabel(BDDMockito.any())).thenReturn(mockEntity);

		scanningService.doPullRequestScan(mockPR);

		// An open PR is still scanned, and is not resolved by this path.
		BDDMockito.verify(mockScanRegistrationService).getCodeScanners();
		BDDMockito.verify(mockScanResultService, BDDMockito.never())
				.markPrResolved(BDDMockito.any(), BDDMockito.anyBoolean());
	}

	@Test
	public void testDoPullRequestScanPreservesOriginalSubmissionTime() throws Exception {
		setupDefaultMocks();
		BDDMockito.when(mockScanRegistrationService.hasCodeScanners()).thenReturn(true);
		long originalSubmittedAt = 1234L;
		BDDMockito.when(mockPR.getSubmitTime()).thenReturn(originalSubmittedAt);

		PullRequest refreshed = BDDMockito.mock(PullRequest.class);
		BDDMockito.when(refreshed.getState()).thenReturn(PullRequestState.ACTIVE);
		BDDMockito.when(refreshed.getSubmitTime()).thenReturn(9999L);
		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockApi.updatePRData(mockPR)).thenReturn(refreshed);
		ApiIntegrationEntity mockEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(mockEntity.getScanType()).thenReturn(CodeScanType.PULL_REQUEST);
		BDDMockito.when(mockEntity.createApi()).thenReturn(mockApi);
		BDDMockito.when(mockApiService.findByLabel(BDDMockito.any())).thenReturn(mockEntity);

		PRScanningService service = Mockito.spy(scanningService);
		ScanExecutionResult queued = new ScanExecutionResult(PRScanSubmitResult.QUEUED, null, null);
		BDDMockito.doReturn(queued).when(service).executeScan(BDDMockito.eq(refreshed),
				BDDMockito.eq(mockApi),
				BDDMockito.any(RulesetEntity.class), BDDMockito.isNull(),
				BDDMockito.eq(originalSubmittedAt));

		Assertions.assertEquals(PRScanSubmitResult.QUEUED, service.doPullRequestScan(mockPR));
		BDDMockito.verify(service).executeScan(BDDMockito.eq(refreshed),
				BDDMockito.eq(mockApi),
				BDDMockito.any(RulesetEntity.class), BDDMockito.isNull(),
				BDDMockito.eq(originalSubmittedAt));
	}

	@Test
	public void testDoPullRequestScanPublishesToSqsWhenSubmissionEnabled() throws Exception {
		// Check local integration capability before queueing; no SCM calls or scanner work.
		PRScanningService sqsScanningService = newScanningServiceWithSqsSubmissionEnabled();
		BDDMockito.when(mockSqsScanQueueService.isEnabled()).thenReturn(true);
		BDDMockito.when(mockSqsScanQueueService.publish(BDDMockito.any())).thenReturn(true);
		BDDMockito.when(mockPR.getApiLabel()).thenReturn("label");
		BDDMockito.when(mockPR.getRepoName()).thenReturn("repo");
		BDDMockito.when(mockPR.getPrId()).thenReturn("1");
		BDDMockito.when(mockPR.getCommitHash()).thenReturn("abc123");
		BDDMockito.when(mockPR.getPRString()).thenReturn("repo-1");

		PRScanSubmitResult result = sqsScanningService.doPullRequestScan(mockPR);

		Assertions.assertEquals(PRScanSubmitResult.QUEUED, result);
		ArgumentCaptor<ScanRequestMessage> captor =
				ArgumentCaptor.forClass(ScanRequestMessage.class);
		BDDMockito.verify(mockSqsScanQueueService).publish(captor.capture());
		Assertions.assertEquals("label", captor.getValue().apiLabel());
		Assertions.assertEquals("repo", captor.getValue().repoName());
		Assertions.assertEquals("1", captor.getValue().prId());
		Assertions.assertEquals("abc123", captor.getValue().commitHash());
		// Only a read of what is already stored: nothing is created for a repository that has
		// merely been named, and no scanner or provider is touched
		BDDMockito.verify(mockRepoService).findExisting("label", "repo");
		BDDMockito.verifyNoMoreInteractions(mockRepoService);
		BDDMockito.verifyNoInteractions(mockScanRegistrationService);
		BDDMockito.verify(mockApiService).findByLabel("label");
	}

	@Test
	public void testDoPullRequestScanAnswersPausedBeforeQueueingWhenSqsSubmissionEnabled()
			throws Exception {
		PRScanningService sqsScanningService = newScanningServiceWithSqsSubmissionEnabled();
		BDDMockito.when(mockSqsScanQueueService.isEnabled()).thenReturn(true);
		BDDMockito.when(mockPR.getApiLabel()).thenReturn("label");
		BDDMockito.when(mockPR.getRepoName()).thenReturn("repo");
		BDDMockito.when(mockPR.getPRString()).thenReturn("repo-1");
		RepositoryEntity paused = new RepositoryEntity();
		paused.setScanningPaused(true);
		BDDMockito.when(mockRepoService.findExisting("label", "repo"))
				.thenReturn(java.util.Optional.of(paused));

		PRScanSubmitResult result = sqsScanningService.doPullRequestScan(mockPR);

		Assertions.assertEquals(PRScanSubmitResult.PAUSED, result);
		BDDMockito.verify(mockSqsScanQueueService, BDDMockito.never()).publish(BDDMockito.any());
	}

	@Test
	public void testDoPullRequestScanAnswersNoRulesetBeforeQueueingWhenSqsSubmissionEnabled()
			throws Exception {
		PRScanningService sqsScanningService = newScanningServiceWithSqsSubmissionEnabled();
		BDDMockito.when(mockSqsScanQueueService.isEnabled()).thenReturn(true);
		BDDMockito.when(mockPR.getApiLabel()).thenReturn("label");
		BDDMockito.when(mockPR.getRepoName()).thenReturn("repo");
		BDDMockito.when(mockPR.getPRString()).thenReturn("repo-1");
		BDDMockito.when(mockRepoService.findExisting("label", "repo"))
				.thenReturn(java.util.Optional.of(new RepositoryEntity()));

		PRScanSubmitResult result = sqsScanningService.doPullRequestScan(mockPR);

		Assertions.assertEquals(PRScanSubmitResult.NO_RULESET, result);
		BDDMockito.verify(mockSqsScanQueueService, BDDMockito.never()).publish(BDDMockito.any());
	}

	@Test
	public void testRequirePullRequestExistsRefusesAPullRequestTheProviderDoesNotKnow()
			throws Exception {
		var api = BDDMockito.mock(IScmApi.class);
		var entity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(entity.getScanType()).thenReturn(CodeScanType.PULL_REQUEST);
		BDDMockito.when(entity.createApi()).thenReturn(api);
		BDDMockito.when(mockApiService.findByLabel("label")).thenReturn(entity);
		BDDMockito.when(api.updatePRData(BDDMockito.any()))
				.thenThrow(new com.tracelink.appsec.watchtower.core.exception.PullRequestNotFoundException(
						"Pull request not found"));
		PullRequest typed = new PullRequest("label");
		typed.setRepoName("repo");
		typed.setPrId("999999");

		Assertions.assertThrows(
				com.tracelink.appsec.watchtower.core.exception.PullRequestNotFoundException.class,
				() -> scanningService.requirePullRequestExists(typed));
	}

	@Test
	public void testRequirePullRequestExistsLetsAnUnreachableProviderThrough() throws Exception {
		var api = BDDMockito.mock(IScmApi.class);
		var entity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(entity.getScanType()).thenReturn(CodeScanType.PULL_REQUEST);
		BDDMockito.when(entity.createApi()).thenReturn(api);
		BDDMockito.when(mockApiService.findByLabel("label")).thenReturn(entity);
		BDDMockito.when(api.updatePRData(BDDMockito.any()))
				.thenThrow(new IllegalStateException("provider unreachable"));
		PullRequest typed = new PullRequest("label");
		typed.setRepoName("repo");
		typed.setPrId("7");

		Assertions.assertDoesNotThrow(() -> scanningService.requirePullRequestExists(typed));
	}

	@Test
	public void testRequirePullRequestExistsRefusesAnIntegrationThatCannotScanPullRequests() {
		var image = new com.tracelink.appsec.watchtower.core.scan.image.api.ecr.EcrIntegrationEntity();
		BDDMockito.when(mockApiService.findByLabel(BDDMockito.any())).thenReturn(image);
		PullRequest typed = new PullRequest("label");
		typed.setRepoName("repo");
		typed.setPrId("7");

		Assertions.assertThrows(ScanRejectedException.class,
				() -> scanningService.requirePullRequestExists(typed));
	}

	@Test
	public void aManualSubmitAndAWebhookQueueTheSamePullRequestUnderOneName() throws Exception {
		// The form takes what is typed; the webhook names the repository by its slug. The SQS
		// group and duplicate checks compare names exactly, so both must arrive as the slug.
		PRScanningService sqsScanningService = newScanningServiceWithSqsSubmissionEnabled();
		BDDMockito.when(mockSqsScanQueueService.isEnabled()).thenReturn(true);
		BDDMockito.when(mockSqsScanQueueService.publish(BDDMockito.any())).thenReturn(true);
		ManualPullRequest typed = new ManualPullRequest();
		typed.setApiLabel("bb");
		typed.setRepo(" Payments API ");
		typed.setPrid("7");
		PullRequest fromWebhook = new PullRequest("bb");
		fromWebhook.setRepoName("payments-api");
		fromWebhook.setPrId("7");
		PullRequest fromRecovery = new PullRequest("bb");
		fromRecovery.setRepoName("Payments-API");
		fromRecovery.setPrId("7");

		sqsScanningService.doPullRequestScan(typed.createPR());
		sqsScanningService.doPullRequestScan(fromWebhook);
		sqsScanningService.doPullRequestScan(fromRecovery);

		ArgumentCaptor<ScanRequestMessage> captor =
				ArgumentCaptor.forClass(ScanRequestMessage.class);
		BDDMockito.verify(mockSqsScanQueueService, BDDMockito.times(3)).publish(captor.capture());
		Assertions.assertEquals(List.of("payments-api", "payments-api", "payments-api"),
				captor.getAllValues().stream().map(ScanRequestMessage::repoName).toList());
	}

	@Test
	public void testDoPullRequestScanRunsLocallyWhenSqsConfiguredButFlagDisabled()
			throws Exception {
		// The queue-url being set (e.g. left over from 4.1-4.3 testing) must not change
		// submission behavior on its own - only the explicit flag does.
		setupDefaultMocks();
		BDDMockito.when(mockScanRegistrationService.hasCodeScanners()).thenReturn(true);
		BDDMockito.when(mockScanRegistrationService.getCodeScanners())
				.thenReturn(Collections.singleton(new MockScanner()));
		BDDMockito.when(mockSqsScanQueueService.isEnabled()).thenReturn(true);

		PullRequest active = BDDMockito.mock(PullRequest.class);
		BDDMockito.when(active.getState()).thenReturn(PullRequestState.ACTIVE);

		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockApi.updatePRData(BDDMockito.any())).thenReturn(active);
		ApiIntegrationEntity mockEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(mockEntity.getScanType()).thenReturn(CodeScanType.PULL_REQUEST);
		BDDMockito.when(mockEntity.createApi()).thenReturn(mockApi);
		BDDMockito.when(mockApiService.findByLabel(BDDMockito.any())).thenReturn(mockEntity);

		// scanningService (from @BeforeEach) has sqsSubmissionEnabled=false.
		PRScanSubmitResult result = scanningService.doPullRequestScan(mockPR);

		Assertions.assertEquals(PRScanSubmitResult.QUEUED, result);
		BDDMockito.verify(mockSqsScanQueueService, BDDMockito.never())
				.publish(BDDMockito.any());
		BDDMockito.verify(mockScanRegistrationService).getCodeScanners();
	}

	@Test
	public void testExecuteScanNeverPublishesToSqs() throws Exception {
		// SqsScanConsumer calls executeScan() directly; it must never re-publish,
		// which would loop.
		PRScanningService sqsScanningService = newScanningServiceWithSqsSubmissionEnabled();
		RulesetEntity ruleset = new RulesetEntity();
		ruleset.setRules(Collections.singleton(new MockRuleEntity()));

		PullRequest active = BDDMockito.mock(PullRequest.class);
		BDDMockito.when(active.getState()).thenReturn(PullRequestState.ACTIVE);
		BDDMockito.when(active.getCommitHash()).thenReturn("abc123");

		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockScanRegistrationService.getCodeScanners())
				.thenReturn(Collections.singleton(new MockScanner()));

		ScanExecutionResult executionResult = sqsScanningService.executeScan(active, mockApi, ruleset);

		Assertions.assertEquals(PRScanSubmitResult.QUEUED, executionResult.result());
		Assertions.assertNotNull(executionResult.agent());
		Assertions.assertNotNull(executionResult.future());
		BDDMockito.verifyNoInteractions(mockSqsScanQueueService);
	}

	@Test
	public void testDoPullRequestScanIncrementsQueuedCounter() throws Exception {
		// IMPROVEMENT_PLAN.md item 6.6 smoke test: a queued scan bumps the
		// watchtower.scan.queued{type=pr} counter that /actuator/metrics exposes.
		setupDefaultMocks();
		BDDMockito.when(mockScanRegistrationService.hasCodeScanners()).thenReturn(true);
		BDDMockito.when(mockScanRegistrationService.getCodeScanners())
				.thenReturn(Collections.singleton(new MockScanner()));
		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockApi.updatePRData(BDDMockito.any())).thenAnswer(e -> e.getArgument(0));
		ApiIntegrationEntity mockEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(mockEntity.getScanType()).thenReturn(CodeScanType.PULL_REQUEST);
		BDDMockito.when(mockEntity.createApi()).thenReturn(mockApi);
		BDDMockito.when(mockApiService.findByLabel(BDDMockito.any())).thenReturn(mockEntity);

		double before = meterRegistry.get("watchtower.scan.queued").tag("type", "pr").counter()
				.count();
		scanningService.doPullRequestScan(mockPR);
		double after = meterRegistry.get("watchtower.scan.queued").tag("type", "pr").counter()
				.count();

		MatcherAssert.assertThat(after, Matchers.equalTo(before + 1));
	}

	@Test
	public void testQueueDepthGaugeIsRegistered() {
		// IMPROVEMENT_PLAN.md item 6.6: watchtower.scan.queue.depth{type=pr} must be
		// present in /actuator/metrics even before any scan is queued.
		double depth = meterRegistry.get("watchtower.scan.queue.depth").tag("type", "pr").gauge()
				.value();
		MatcherAssert.assertThat(depth, Matchers.equalTo(0.0));
	}

	@Test
	public void testDuplicateWebhookForTheSameCommitQueuesOneScan() throws Exception {
		// Bitbucket fires several events per push and retries deliveries, so the same
		// commit arrives more than once. Without dedup each delivery downloaded the same
		// zip and posted its own comment.
		setupDefaultMocks();
		BDDMockito.when(mockScanRegistrationService.hasCodeScanners()).thenReturn(true);
		BDDMockito.when(mockScanRegistrationService.getCodeScanners())
				.thenReturn(Collections.singleton(new MockScanner()));

		PullRequest pr = BDDMockito.mock(PullRequest.class);
		BDDMockito.when(pr.getState()).thenReturn(PullRequestState.ACTIVE);
		BDDMockito.when(pr.getCommitHash()).thenReturn("abc123");

		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockApi.updatePRData(BDDMockito.any())).thenReturn(pr);
		ApiIntegrationEntity mockEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(mockEntity.getScanType()).thenReturn(CodeScanType.PULL_REQUEST);
		BDDMockito.when(mockEntity.createApi()).thenReturn(mockApi);
		BDDMockito.when(mockApiService.findByLabel(BDDMockito.any())).thenReturn(mockEntity);

		// Paused, so the first scan cannot finish and clear the in-flight entry before
		// the second submission arrives. Without this the test races the thread pool.
		scanningService.pauseExecution();
		try {
			scanningService.doPullRequestScan(mockPR);
			scanningService.doPullRequestScan(mockPR);
		} finally {
			scanningService.resumeExecution();
		}

		// Only one agent was built, so only one scan was queued.
		BDDMockito.verify(mockScanRegistrationService, BDDMockito.times(1)).getCodeScanners();
	}

	@Test
	public void testDifferentCommitOnTheSamePullRequestIsNotDeduplicated() throws Exception {
		// A force-push is new work, so it must not be mistaken for a duplicate delivery.
		setupDefaultMocks();
		BDDMockito.when(mockScanRegistrationService.hasCodeScanners()).thenReturn(true);
		BDDMockito.when(mockScanRegistrationService.getCodeScanners())
				.thenReturn(Collections.singleton(new MockScanner()));

		PullRequest first = BDDMockito.mock(PullRequest.class);
		BDDMockito.when(first.getState()).thenReturn(PullRequestState.ACTIVE);
		BDDMockito.when(first.getCommitHash()).thenReturn("abc123");
		PullRequest second = BDDMockito.mock(PullRequest.class);
		BDDMockito.when(second.getState()).thenReturn(PullRequestState.ACTIVE);
		BDDMockito.when(second.getCommitHash()).thenReturn("def456");

		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockApi.updatePRData(BDDMockito.any())).thenReturn(first, second);
		ApiIntegrationEntity mockEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(mockEntity.getScanType()).thenReturn(CodeScanType.PULL_REQUEST);
		BDDMockito.when(mockEntity.createApi()).thenReturn(mockApi);
		BDDMockito.when(mockApiService.findByLabel(BDDMockito.any())).thenReturn(mockEntity);

		scanningService.pauseExecution();
		try {
			scanningService.doPullRequestScan(mockPR);
			scanningService.doPullRequestScan(mockPR);
		} finally {
			scanningService.resumeExecution();
		}

		BDDMockito.verify(mockScanRegistrationService, BDDMockito.times(2)).getCodeScanners();
	}

	@Test
	public void testDoPullRequestScanNullRuleset() throws Exception {
		BDDMockito.when(mockPR.getPRString()).thenReturn("Mock PR");
		BDDMockito.when(mockPR.getApiLabel()).thenReturn("label");
		RepositoryEntity repo = new RepositoryEntity();
		BDDMockito
				.when(mockRepoService.upsertRepo(BDDMockito.any(), BDDMockito.any(),
						BDDMockito.any()))
				.thenReturn(repo);
		scanningService.doPullRequestScan(mockPR);
		Assertions.assertEquals(1, logWatcher.getMessages().size());
		Assertions.assertEquals(
				"PR: Mock PR skipped as the repository is not configured with a ruleset.",
				logWatcher.getMessages().get(0));
	}

	@Test
	public void testDoPullRequestScanOfAPausedRepositoryIsSkippedWithoutTouchingTheScm()
			throws Exception {
		BDDMockito.when(mockPR.getPRString()).thenReturn("Mock PR");
		BDDMockito.when(mockPR.getApiLabel()).thenReturn("label");
		RepositoryEntity repo = new RepositoryEntity();
		repo.setRuleset(new RulesetEntity());
		repo.setScanningPaused(true);
		BDDMockito
				.when(mockRepoService.upsertRepo(BDDMockito.any(), BDDMockito.any(),
						BDDMockito.any()))
				.thenReturn(repo);

		Assertions.assertEquals(PRScanSubmitResult.PAUSED,
				scanningService.doPullRequestScan(mockPR));
		Assertions.assertTrue(PRScanSubmitResult.PAUSED.isAccepted());
		Assertions.assertEquals(
				"PR: Mock PR skipped as scanning of the repository is paused.",
				logWatcher.getMessages().get(0));
		BDDMockito.verify(mockApiService).findByLabel("label");
	}

	@Test
	public void testDoPullRequestScanUnknownApiLabel() throws Exception {
		setupDefaultMocks();
		BDDMockito.when(mockScanRegistrationService.hasCodeScanners()).thenReturn(true);
		BDDMockito.when(mockPR.getApiLabel()).thenReturn("stale-label");
		// No api integration is registered under this label
		BDDMockito.when(mockApiService.findByLabel(BDDMockito.any())).thenReturn(null);

		try {
			scanningService.doPullRequestScan(mockPR);
			Assertions.fail("Should have thrown exception");
		} catch (ScanRejectedException sre) {
			MatcherAssert.assertThat(sre.getMessage(), Matchers.containsString("supports pull request"));
		}
	}

	@Test
	public void testQuiesce() throws ScanRejectedException, ApiIntegrationException {
		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockApi.updatePRData(BDDMockito.any())).thenAnswer(e -> e.getArgument(0));

		// Test when service is quiesced
		scanningService.quiesce();

		try {
			scanningService.doPullRequestScan(mockPR);
			Assertions.fail("Should have thrown exception");
		} catch (ScanRejectedException sre) {
			// correct
		}

		// Test when service is unquiesced
		setupDefaultMocks();
		scanningService.unQuiesce();
		scanningService.doPullRequestScan(mockPR);
		// if this doesn't throw, then we're good.
	}

	@Test
	public void testPause() throws Exception {
		setupDefaultMocks();
		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockApi.updatePRData(BDDMockito.any())).thenAnswer(e -> e.getArgument(0));

		scanningService.pauseExecution();
		scanningService.doPullRequestScan(mockPR);
		Assertions.assertTrue(scanningService.isPaused());
		scanningService.resumeExecution();
		Assertions.assertFalse(scanningService.isPaused());
		Thread.sleep(1000);
		Assertions.assertEquals(0L, scanningService.getTaskNumInQueue());
	}


	@Test
	public void testShutdown() throws Exception {
		setupDefaultMocks();

		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockApi.updatePRData(BDDMockito.any())).thenAnswer(e -> e.getArgument(0));
		ApiIntegrationEntity mockEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(mockEntity.getScanType()).thenReturn(CodeScanType.PULL_REQUEST);
		BDDMockito.when(mockEntity.createApi()).thenReturn(mockApi);

		BDDMockito.when(mockScanRegistrationService.hasCodeScanners()).thenReturn(true);
		BDDMockito.when(mockApiService.findByLabel(BDDMockito.any())).thenReturn(mockEntity);
		scanningService.shutdown();
		try {
			scanningService.doPullRequestScan(mockPR);
			Assertions.fail("Should not have been accepted");
		} catch (TaskRejectedException e) {
			// expected
		}
	}

	@Test
	public void testRecoverFromDowntime() throws Exception {
		String apiLabel = "api";
		String repoName = "repo";

		RepositoryEntity mockRepoEntity = BDDMockito.mock(RepositoryEntity.class);
		BDDMockito.when(mockRepoEntity.getRepoName()).thenReturn(repoName);
		BDDMockito.when(mockRepoEntity.isEnabled()).thenReturn(true);
		BDDMockito.when(mockRepoEntity.isPrActive()).thenReturn(true);
		BDDMockito.when(mockRepoService.getAllRepos(CodeScanType.PULL_REQUEST))
				.thenReturn(
						Collections.singletonMap(apiLabel,
								Collections.singletonList(mockRepoEntity)));

		ApiIntegrationEntity mockApiEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(mockApiEntity.getApiLabel()).thenReturn(apiLabel);
		BDDMockito.when(mockApiEntity.getScanType()).thenReturn(CodeScanType.PULL_REQUEST);
		BDDMockito.when(mockApiService.getAllSettings())
				.thenReturn(Collections.singletonList(mockApiEntity));

		String prSeenReviewedId = "123";
		String prSeenNotReviewedId = "234";
		String prUnknownId = "345";
		PullRequest prSeenReviewed = BDDMockito.mock(PullRequest.class);
		BDDMockito.when(prSeenReviewed.getPrId()).thenReturn(prSeenReviewedId);
		BDDMockito.when(prSeenReviewed.getPRString()).thenReturn("SR");
		BDDMockito.when(prSeenReviewed.getApiLabel()).thenReturn(apiLabel);
		BDDMockito.when(prSeenReviewed.getRepoName()).thenReturn(repoName);

		PullRequest prSeenNotReviewed = BDDMockito.mock(PullRequest.class);
		BDDMockito.when(prSeenNotReviewed.getPrId()).thenReturn(prSeenNotReviewedId);
		BDDMockito.when(prSeenNotReviewed.getPRString()).thenReturn("SNR");
		BDDMockito.when(prSeenNotReviewed.getApiLabel()).thenReturn(apiLabel);
		BDDMockito.when(prSeenNotReviewed.getRepoName()).thenReturn(repoName);

		PullRequest prUnknown = BDDMockito.mock(PullRequest.class);
		BDDMockito.when(prUnknown.getPrId()).thenReturn(prUnknownId);
		BDDMockito.when(prUnknown.getPRString()).thenReturn("U");
		BDDMockito.when(prUnknown.getApiLabel()).thenReturn(apiLabel);
		BDDMockito.when(prUnknown.getRepoName()).thenReturn(repoName);

		IScmApi mockApi = Mockito.mock(IScmApi.class);
		BDDMockito.when(mockApi.getOpenPullRequestsForRepository(repoName))
				.thenReturn(Arrays.asList(prSeenReviewed, prSeenNotReviewed, prUnknown));
		BDDMockito.when(mockApi.isRepositoryActive(BDDMockito.anyString())).thenReturn(true);

		PullRequestContainerEntity prceSeenReviewed =
				BDDMockito.mock(PullRequestContainerEntity.class);
		BDDMockito.when(prceSeenReviewed.getLastReviewedDate()).thenReturn(2L);
		BDDMockito.when(prSeenReviewed.getUpdateTime()).thenReturn(1L);

		PullRequestContainerEntity prceSeenNotReviewed =
				BDDMockito.mock(PullRequestContainerEntity.class);
		BDDMockito.when(prceSeenNotReviewed.getLastReviewedDate()).thenReturn(1L);
		BDDMockito.when(prSeenNotReviewed.getUpdateTime()).thenReturn(2L);

		BDDMockito.when(
				mockScanResultService.getPullRequestByLabelRepoAndId(apiLabel, repoName,
						prSeenReviewedId))
				.thenReturn(prceSeenReviewed);
		BDDMockito.when(
				mockScanResultService.getPullRequestByLabelRepoAndId(apiLabel, repoName,
						prSeenNotReviewedId))
				.thenReturn(prceSeenNotReviewed);
		BDDMockito.when(
				mockScanResultService.getPullRequestByLabelRepoAndId(apiLabel, repoName,
						prUnknownId))
				.thenReturn(null);

		BDDMockito.when(mockRepoService.upsertRepo(CodeScanType.PULL_REQUEST, apiLabel, repoName))
				.thenReturn(mockRepoEntity);
		BDDMockito.when(mockRepoEntity.getRuleset()).thenReturn(new RulesetEntity());

		BDDMockito.when(mockScanRegistrationService.hasCodeScanners()).thenReturn(true);

		BDDMockito.when(mockApiEntity.createApi()).thenReturn(mockApi);
		BDDMockito.when(mockApiService.findByLabel(BDDMockito.any())).thenReturn(mockApiEntity);
		ArgumentCaptor<PullRequest> prCaptor = ArgumentCaptor.forClass(PullRequest.class);

		scanningService.recoverFromDowntime();
		BDDMockito.verify(mockApi, BDDMockito.times(2)).updatePRData(prCaptor.capture());
		List<PullRequest> capturedPrs = prCaptor.getAllValues();
		MatcherAssert.assertThat(capturedPrs, Matchers.hasItems(prUnknown, prSeenNotReviewed));
	}

	@Test
	public void testRecoverFromDowntimeDeadRepo() throws Exception {
		String apiLabel = "api";
		String repoName = "repo";

		RepositoryEntity mockRepoEntity = BDDMockito.mock(RepositoryEntity.class);
		BDDMockito.when(mockRepoEntity.getRepoName()).thenReturn(repoName);
		BDDMockito.when(mockRepoEntity.isEnabled()).thenReturn(true);
		BDDMockito.when(mockRepoEntity.isPrActive()).thenReturn(true);
		BDDMockito.when(mockRepoService.getAllRepos(CodeScanType.PULL_REQUEST))
				.thenReturn(
						Collections.singletonMap(apiLabel,
								Collections.singletonList(mockRepoEntity)));

		ApiIntegrationEntity mockApiEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(mockApiEntity.getApiLabel()).thenReturn(apiLabel);
		BDDMockito.when(mockApiEntity.getScanType()).thenReturn(CodeScanType.PULL_REQUEST);
		BDDMockito.when(mockApiService.getAllSettings())
				.thenReturn(Collections.singletonList(mockApiEntity));

		String prSeenReviewedId = "123";
		String prSeenNotReviewedId = "234";
		String prUnknownId = "345";
		PullRequest prSeenReviewed = BDDMockito.mock(PullRequest.class);
		BDDMockito.when(prSeenReviewed.getPrId()).thenReturn(prSeenReviewedId);
		BDDMockito.when(prSeenReviewed.getPRString()).thenReturn("SR");
		BDDMockito.when(prSeenReviewed.getApiLabel()).thenReturn(apiLabel);
		BDDMockito.when(prSeenReviewed.getRepoName()).thenReturn(repoName);

		PullRequest prSeenNotReviewed = BDDMockito.mock(PullRequest.class);
		BDDMockito.when(prSeenNotReviewed.getPrId()).thenReturn(prSeenNotReviewedId);
		BDDMockito.when(prSeenNotReviewed.getPRString()).thenReturn("SNR");
		BDDMockito.when(prSeenNotReviewed.getApiLabel()).thenReturn(apiLabel);
		BDDMockito.when(prSeenNotReviewed.getRepoName()).thenReturn(repoName);

		PullRequest prUnknown = BDDMockito.mock(PullRequest.class);
		BDDMockito.when(prUnknown.getPrId()).thenReturn(prUnknownId);
		BDDMockito.when(prUnknown.getPRString()).thenReturn("U");
		BDDMockito.when(prUnknown.getApiLabel()).thenReturn(apiLabel);
		BDDMockito.when(prUnknown.getRepoName()).thenReturn(repoName);

		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockApi.getOpenPullRequestsForRepository(repoName))
				.thenReturn(Arrays.asList(prSeenReviewed, prSeenNotReviewed, prUnknown));
		BDDMockito.when(mockApi.isRepositoryActive(BDDMockito.anyString())).thenReturn(false);

		PullRequestContainerEntity prceSeenReviewed =
				BDDMockito.mock(PullRequestContainerEntity.class);
		BDDMockito.when(prceSeenReviewed.getLastReviewedDate()).thenReturn(2L);
		BDDMockito.when(prSeenReviewed.getUpdateTime()).thenReturn(1L);

		PullRequestContainerEntity prceSeenNotReviewed =
				BDDMockito.mock(PullRequestContainerEntity.class);
		BDDMockito.when(prceSeenNotReviewed.getLastReviewedDate()).thenReturn(1L);
		BDDMockito.when(prSeenNotReviewed.getUpdateTime()).thenReturn(2L);

		BDDMockito.when(
				mockScanResultService.getPullRequestByLabelRepoAndId(apiLabel, repoName,
						prSeenReviewedId))
				.thenReturn(prceSeenReviewed);
		BDDMockito.when(
				mockScanResultService.getPullRequestByLabelRepoAndId(apiLabel, repoName,
						prSeenNotReviewedId))
				.thenReturn(prceSeenNotReviewed);
		BDDMockito.when(
				mockScanResultService.getPullRequestByLabelRepoAndId(apiLabel, repoName,
						prUnknownId))
				.thenReturn(null);

		BDDMockito.when(mockRepoService.upsertRepo(CodeScanType.PULL_REQUEST, apiLabel, repoName))
				.thenReturn(mockRepoEntity);
		BDDMockito.when(mockRepoEntity.getRuleset()).thenReturn(new RulesetEntity());

		BDDMockito.when(mockApiEntity.createApi()).thenReturn(mockApi);

		BDDMockito.when(mockScanRegistrationService.hasCodeScanners()).thenReturn(true);
		BDDMockito.when(mockApiService.findByLabel(BDDMockito.any())).thenReturn(mockApiEntity);

		ArgumentCaptor<PullRequest> prCaptor = ArgumentCaptor.forClass(PullRequest.class);

		scanningService.recoverFromDowntime();
		BDDMockito.verify(mockApi, BDDMockito.times(0)).updatePRData(prCaptor.capture());
		BDDMockito.verify(mockRepoService).disableRepository(mockRepoEntity);
	}

	@Test
	public void testRecoverFromDowntimeSkipsReposKnownOnlyFromCatalogSync() throws Exception {
		RepositoryEntity syncedOnly = BDDMockito.mock(RepositoryEntity.class);
		BDDMockito.when(syncedOnly.isEnabled()).thenReturn(true);
		BDDMockito.when(syncedOnly.isPrActive()).thenReturn(false);
		BDDMockito.when(mockRepoService.getAllRepos(CodeScanType.PULL_REQUEST))
				.thenReturn(Collections.singletonMap("api", Collections.singletonList(syncedOnly)));
		ApiIntegrationEntity mockApiEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(mockApiEntity.getApiLabel()).thenReturn("api");
		BDDMockito.when(mockApiEntity.getScanType()).thenReturn(CodeScanType.PULL_REQUEST);
		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockApiEntity.createApi()).thenReturn(mockApi);
		BDDMockito.when(mockApiService.getAllSettings())
				.thenReturn(Collections.singletonList(mockApiEntity));

		scanningService.recoverFromDowntime();

		BDDMockito.verify(mockApi, BDDMockito.never()).isRepositoryActive(BDDMockito.anyString());
		BDDMockito.verify(mockApi, BDDMockito.never())
				.getOpenPullRequestsForRepository(BDDMockito.anyString());
		BDDMockito.verify(mockRepoService, BDDMockito.never()).disableRepository(syncedOnly);
	}

	@Test
	public void testRecoverFromDowntimeAlreadyDeadRepo() throws Exception {
		String apiLabel = "api";
		String repoName = "repo";

		RepositoryEntity mockRepoEntity = BDDMockito.mock(RepositoryEntity.class);
		BDDMockito.when(mockRepoEntity.getRepoName()).thenReturn(repoName);
		BDDMockito.when(mockRepoEntity.isEnabled()).thenReturn(false);
		BDDMockito.when(mockRepoService.getAllRepos(CodeScanType.PULL_REQUEST))
				.thenReturn(
						Collections.singletonMap(apiLabel,
								Collections.singletonList(mockRepoEntity)));

		ApiIntegrationEntity mockApiEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(mockApiEntity.getApiLabel()).thenReturn(apiLabel);
		BDDMockito.when(mockApiEntity.getScanType()).thenReturn(CodeScanType.PULL_REQUEST);
		BDDMockito.when(mockApiService.getAllSettings())
				.thenReturn(Collections.singletonList(mockApiEntity));

		String prSeenReviewedId = "123";
		String prSeenNotReviewedId = "234";
		String prUnknownId = "345";
		PullRequest prSeenReviewed = BDDMockito.mock(PullRequest.class);
		BDDMockito.when(prSeenReviewed.getPrId()).thenReturn(prSeenReviewedId);
		BDDMockito.when(prSeenReviewed.getPRString()).thenReturn("SR");
		BDDMockito.when(prSeenReviewed.getApiLabel()).thenReturn(apiLabel);
		BDDMockito.when(prSeenReviewed.getRepoName()).thenReturn(repoName);

		PullRequest prSeenNotReviewed = BDDMockito.mock(PullRequest.class);
		BDDMockito.when(prSeenNotReviewed.getPrId()).thenReturn(prSeenNotReviewedId);
		BDDMockito.when(prSeenNotReviewed.getPRString()).thenReturn("SNR");
		BDDMockito.when(prSeenNotReviewed.getApiLabel()).thenReturn(apiLabel);
		BDDMockito.when(prSeenNotReviewed.getRepoName()).thenReturn(repoName);

		PullRequest prUnknown = BDDMockito.mock(PullRequest.class);
		BDDMockito.when(prUnknown.getPrId()).thenReturn(prUnknownId);
		BDDMockito.when(prUnknown.getPRString()).thenReturn("U");
		BDDMockito.when(prUnknown.getApiLabel()).thenReturn(apiLabel);
		BDDMockito.when(prUnknown.getRepoName()).thenReturn(repoName);

		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockApi.getOpenPullRequestsForRepository(repoName))
				.thenReturn(Arrays.asList(prSeenReviewed, prSeenNotReviewed, prUnknown));
		BDDMockito.when(mockApi.isRepositoryActive(BDDMockito.anyString())).thenReturn(false);

		PullRequestContainerEntity prceSeenReviewed =
				BDDMockito.mock(PullRequestContainerEntity.class);
		BDDMockito.when(prceSeenReviewed.getLastReviewedDate()).thenReturn(2L);
		BDDMockito.when(prSeenReviewed.getUpdateTime()).thenReturn(1L);

		PullRequestContainerEntity prceSeenNotReviewed =
				BDDMockito.mock(PullRequestContainerEntity.class);
		BDDMockito.when(prceSeenNotReviewed.getLastReviewedDate()).thenReturn(1L);
		BDDMockito.when(prSeenNotReviewed.getUpdateTime()).thenReturn(2L);

		BDDMockito.when(
				mockScanResultService.getPullRequestByLabelRepoAndId(apiLabel, repoName,
						prSeenReviewedId))
				.thenReturn(prceSeenReviewed);
		BDDMockito.when(
				mockScanResultService.getPullRequestByLabelRepoAndId(apiLabel, repoName,
						prSeenNotReviewedId))
				.thenReturn(prceSeenNotReviewed);
		BDDMockito.when(
				mockScanResultService.getPullRequestByLabelRepoAndId(apiLabel, repoName,
						prUnknownId))
				.thenReturn(null);

		BDDMockito.when(mockRepoService.upsertRepo(CodeScanType.PULL_REQUEST, apiLabel, repoName))
				.thenReturn(mockRepoEntity);
		BDDMockito.when(mockRepoEntity.getRuleset()).thenReturn(new RulesetEntity());

		BDDMockito.when(mockScanRegistrationService.hasCodeScanners()).thenReturn(true);

		ArgumentCaptor<PullRequest> prCaptor = ArgumentCaptor.forClass(PullRequest.class);

		scanningService.recoverFromDowntime();
		BDDMockito.verify(mockApi, BDDMockito.times(0)).updatePRData(prCaptor.capture());
		BDDMockito.verify(mockRepoService, BDDMockito.times(0)).disableRepository(mockRepoEntity);
	}

	@Test
	public void testRecoverFromDowntimeSkipsBBPollingWhenSqsSubmissionEnabled() throws Exception {
		// IMPROVEMENT_PLAN.md item 4.6: when SQS submission is enabled and configured,
		// PRs queued before the restart are still sitting in SQS - BB polling recovery
		// would be redundant, expensive work that risks triggering BB rate limits right
		// at startup.
		PRScanningService sqsScanningService = newScanningServiceWithSqsSubmissionEnabled();
		BDDMockito.when(mockSqsScanQueueService.isEnabled()).thenReturn(true);

		sqsScanningService.recoverFromDowntime();

		BDDMockito.verifyNoInteractions(mockApiService);
		BDDMockito.verifyNoInteractions(mockRepoService);
	}

	@Test
	public void testRecoverFromDowntimeStillPollsBBWhenFlagEnabledButSqsNotConfigured()
			throws Exception {
		// The queue-url being set on its own must not change recovery behavior either -
		// only the explicit flag AND SqsScanQueueService.isEnabled() together do, same
		// double-gate as 4.4/4.5.
		PRScanningService sqsScanningService = newScanningServiceWithSqsSubmissionEnabled();
		BDDMockito.when(mockSqsScanQueueService.isEnabled()).thenReturn(false);
		BDDMockito.when(mockApiService.getAllSettings()).thenReturn(Collections.emptyList());

		sqsScanningService.recoverFromDowntime();

		BDDMockito.verify(mockApiService).getAllSettings();
	}

	private void setupDefaultMocks() throws ScanRejectedException {
		RulesetEntity ruleset = new RulesetEntity();
		ruleset.setRules(Collections.singleton(new MockRuleEntity()));
		RepositoryEntity repo = new RepositoryEntity();
		repo.setRuleset(ruleset);
		BDDMockito.when(
				mockRepoService.upsertRepo(BDDMockito.any(), BDDMockito.any(), BDDMockito.any()))
				.thenReturn(repo);
	}

	private class MockScanner implements ICodeScanner {

		@Override
		public CodeScanReport scan(CodeScanConfig config) {
			return null;
		}

		@Override
		public List<Class<? extends RuleDto>> getSupportedRuleClass() {
			return null;
		}
	}
}
