package com.tracelink.appsec.watchtower.core.scan.code.pr.service;

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
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.core.task.TaskRejectedException;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.logging.CoreLogWatchExtension;
import com.tracelink.appsec.watchtower.core.logging.LogsService;
import com.tracelink.appsec.watchtower.core.mock.MockRuleEntity;
import com.tracelink.appsec.watchtower.core.module.scanner.AbstractCodeScanner;
import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.api.APIIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.api.APIIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.api.ApiFactoryService;
import com.tracelink.appsec.watchtower.core.scan.api.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.api.scm.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryService;

import ch.qos.logback.classic.Level;

@ExtendWith(SpringExtension.class)
public class PRScanningServiceTest {
	@RegisterExtension
	public CoreLogWatchExtension logWatcher =
			CoreLogWatchExtension.forClass(PRScanningService.class);

	@MockBean
	private ApiFactoryService mockScanFactory;

	@MockBean
	private LogsService mockLogsService;

	@MockBean
	private RepositoryService mockRepoService;

	@MockBean
	private PRScanResultService mockScanResultService;

	@MockBean
	private ScanRegistrationService mockScanRegistrationService;

	@MockBean
	private APIIntegrationService mockApiService;

	@Mock
	private PullRequest mockPR;

	private PRScanningService scanningService;

	@BeforeEach
	public void setup() {
		BDDMockito.when(mockLogsService.getLogsLevel()).thenReturn(Level.INFO);
		this.scanningService =
				new PRScanningService(mockScanFactory, mockLogsService, mockRepoService,
						mockScanResultService, mockScanRegistrationService, mockApiService, 2,
						false);
	}

	@Test
	public void testDoPullRequestScan() throws Exception {
		setupDefaultMocks();

		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockScanFactory.createApiForApiEntity(BDDMockito.any()))
				.thenReturn(mockApi);
		BDDMockito.when(mockApi.updatePRData(BDDMockito.any())).thenAnswer(e -> e.getArgument(0));
		// Test that scan runs as expected
		BDDMockito.when(mockScanRegistrationService.isEmpty()).thenReturn(false);
		BDDMockito.when(mockScanRegistrationService.getScanners(CodeScanConfig.class))
				.thenReturn(Collections.singleton(new MockScanner()));
		scanningService.doPullRequestScan(mockPR);
		// ran without exceptions is expected
	}

	@Test
	public void testDoPullRequestScanNullRuleset() throws Exception {
		BDDMockito.when(mockPR.getPRString()).thenReturn("Mock PR");
		BDDMockito.when(mockPR.getApiLabel()).thenReturn("label");
		RepositoryEntity repo = new RepositoryEntity();
		BDDMockito
				.when(mockRepoService.upsertRepo(BDDMockito.any(),
						BDDMockito.any()))
				.thenReturn(repo);
		scanningService.doPullRequestScan(mockPR);
		BDDMockito.verify(mockScanFactory, BDDMockito.times(0))
				.createApiForApiEntity(BDDMockito.any());
		Assertions.assertEquals(1, logWatcher.getMessages().size());
		Assertions.assertEquals(
				"PR: Mock PR skipped as the repository is not configured with a ruleset.",
				logWatcher.getMessages().get(0));
	}

	@Test
	public void testQuiesce() throws ScanRejectedException, ApiIntegrationException {
		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockScanFactory.createApiForApiEntity(BDDMockito.any()))
				.thenReturn(mockApi);
		BDDMockito.when(mockApi.updatePRData(BDDMockito.any())).thenAnswer(e -> e.getArgument(0));

		// Test when service is quiesced
		scanningService.quiesce();

		try {
			scanningService.doPullRequestScan(mockPR);
			Assertions.fail("Should have thrown exception");
		} catch (ScanRejectedException sre) {
			// correct
		}

		BDDMockito.verify(mockScanFactory, BDDMockito.times(0))
				.createApiForApiEntity(BDDMockito.any());
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
		BDDMockito.when(mockScanFactory.createApiForApiEntity(BDDMockito.any()))
				.thenReturn(mockApi);
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
		BDDMockito.when(mockScanFactory.createApiForApiEntity(BDDMockito.any()))
				.thenReturn(mockApi);
		BDDMockito.when(mockApi.updatePRData(BDDMockito.any())).thenAnswer(e -> e.getArgument(0));

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
		BDDMockito.when(mockRepoService.getAllRepos())
				.thenReturn(
						Collections.singletonMap(apiLabel,
								Collections.singletonList(mockRepoEntity)));

		APIIntegrationEntity mockApiEntity = BDDMockito.mock(APIIntegrationEntity.class);
		BDDMockito.when(mockApiEntity.getApiLabel()).thenReturn(apiLabel);
		BDDMockito.when(mockApiService.getAllSettings())
				.thenReturn(Collections.singletonList(mockApiEntity));
		BDDMockito.when(mockApiService.findByLabel(apiLabel)).thenReturn(mockApiEntity);

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
		BDDMockito.when(mockApi.isRepositoryActive(BDDMockito.anyString())).thenReturn(true);

		BDDMockito.when(mockScanFactory.createApiForApiEntity(mockApiEntity)).thenReturn(mockApi);

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

		BDDMockito.when(mockRepoService.upsertRepo(apiLabel, repoName)).thenReturn(mockRepoEntity);
		BDDMockito.when(mockRepoEntity.getRuleset()).thenReturn(new RulesetEntity());

		BDDMockito.when(mockScanRegistrationService.isEmpty()).thenReturn(false);
		BDDMockito.when(mockScanFactory.createApiForApiEntity(mockApiEntity)).thenReturn(mockApi);

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
		BDDMockito.when(mockRepoService.getAllRepos())
				.thenReturn(
						Collections.singletonMap(apiLabel,
								Collections.singletonList(mockRepoEntity)));

		APIIntegrationEntity mockApiEntity = BDDMockito.mock(APIIntegrationEntity.class);
		BDDMockito.when(mockApiEntity.getApiLabel()).thenReturn(apiLabel);
		BDDMockito.when(mockApiService.getAllSettings())
				.thenReturn(Collections.singletonList(mockApiEntity));
		BDDMockito.when(mockApiService.findByLabel(apiLabel)).thenReturn(mockApiEntity);

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

		BDDMockito.when(mockScanFactory.createApiForApiEntity(mockApiEntity)).thenReturn(mockApi);

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

		BDDMockito.when(mockRepoService.upsertRepo(apiLabel, repoName)).thenReturn(mockRepoEntity);
		BDDMockito.when(mockRepoEntity.getRuleset()).thenReturn(new RulesetEntity());

		BDDMockito.when(mockScanRegistrationService.isEmpty()).thenReturn(false);
		BDDMockito.when(mockScanFactory.createApiForApiEntity(mockApiEntity)).thenReturn(mockApi);

		ArgumentCaptor<PullRequest> prCaptor = ArgumentCaptor.forClass(PullRequest.class);

		scanningService.recoverFromDowntime();
		BDDMockito.verify(mockApi, BDDMockito.times(0)).updatePRData(prCaptor.capture());
		BDDMockito.verify(mockRepoService).disableRepo(mockRepoEntity);
	}

	@Test
	public void testRecoverFromDowntimeAlreadyDeadRepo() throws Exception {
		String apiLabel = "api";
		String repoName = "repo";

		RepositoryEntity mockRepoEntity = BDDMockito.mock(RepositoryEntity.class);
		BDDMockito.when(mockRepoEntity.getRepoName()).thenReturn(repoName);
		BDDMockito.when(mockRepoEntity.isEnabled()).thenReturn(false);
		BDDMockito.when(mockRepoService.getAllRepos())
				.thenReturn(
						Collections.singletonMap(apiLabel,
								Collections.singletonList(mockRepoEntity)));

		APIIntegrationEntity mockApiEntity = BDDMockito.mock(APIIntegrationEntity.class);
		BDDMockito.when(mockApiEntity.getApiLabel()).thenReturn(apiLabel);
		BDDMockito.when(mockApiService.getAllSettings())
				.thenReturn(Collections.singletonList(mockApiEntity));
		BDDMockito.when(mockApiService.findByLabel(apiLabel)).thenReturn(mockApiEntity);

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

		BDDMockito.when(mockScanFactory.createApiForApiEntity(mockApiEntity)).thenReturn(mockApi);

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

		BDDMockito.when(mockRepoService.upsertRepo(apiLabel, repoName)).thenReturn(mockRepoEntity);
		BDDMockito.when(mockRepoEntity.getRuleset()).thenReturn(new RulesetEntity());

		BDDMockito.when(mockScanRegistrationService.isEmpty()).thenReturn(false);
		BDDMockito.when(mockScanFactory.createApiForApiEntity(mockApiEntity)).thenReturn(mockApi);

		ArgumentCaptor<PullRequest> prCaptor = ArgumentCaptor.forClass(PullRequest.class);

		scanningService.recoverFromDowntime();
		BDDMockito.verify(mockApi, BDDMockito.times(0)).updatePRData(prCaptor.capture());
		BDDMockito.verify(mockRepoService, BDDMockito.times(0)).disableRepo(mockRepoEntity);
	}

	private void setupDefaultMocks() throws ScanRejectedException {
		RulesetEntity ruleset = new RulesetEntity();
		ruleset.setRules(Collections.singleton(new MockRuleEntity()));
		RepositoryEntity repo = new RepositoryEntity();
		repo.setRuleset(ruleset);
		BDDMockito.when(mockRepoService.upsertRepo(BDDMockito.any(), BDDMockito.any()))
				.thenReturn(repo);
	}

	private class MockScanner extends AbstractCodeScanner {

		@Override
		public ScanReport scan(CodeScanConfig config) {
			return null;
		}

		@Override
		public Class<? extends RuleDto> getSupportedRuleClass() {
			return null;
		}
	}
}
