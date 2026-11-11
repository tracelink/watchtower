package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.BDDMockito;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.core.env.Environment;
import org.springframework.data.domain.PageImpl;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.exception.PullRequestNotFoundException;
import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.logging.CoreLogWatchExtension;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestState;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestTest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestSyncSettingsEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;

@ExtendWith(SpringExtension.class)
public class PullRequestSynchronizerTest {


	@RegisterExtension
	public CoreLogWatchExtension logWatcher =
			CoreLogWatchExtension.forClass(PullRequestSynchronizer.class);

	@MockitoBean
	private PRContainerRepository mockPrRepo;

	@MockitoBean
	private Environment mockEnvironment;

	@MockitoBean
	private PRScanResultService mockResultService;

	@MockitoBean
	private ApiIntegrationService mockApiIntegrationService;

	@MockitoBean
	private RepositoryRepository mockRepoRepo;

	@MockitoBean
	private PullRequestSyncSettingsService mockSyncSettingsService;

	private PullRequestSynchronizer prSync;

	@BeforeEach
	public void setup() {
		prSync = new PullRequestSynchronizer(mockEnvironment, mockPrRepo, mockResultService,
				mockApiIntegrationService, mockRepoRepo, mockSyncSettingsService);

		// Due by default: no prior sync recorded, so every test's sync is due unless a test
		// explicitly overrides this to exercise the not-due-yet skip path.
		PullRequestSyncSettingsEntity settings = new PullRequestSyncSettingsEntity();
		BDDMockito.when(mockSyncSettingsService.getSettings()).thenReturn(settings);
		// No inactive repos by default; tests exercising that filter override this.
		BDDMockito.when(mockRepoRepo.findByLastReviewedDateBefore(BDDMockito.anyLong()))
				.thenReturn(Collections.emptyList());
		BDDMockito.when(mockPrRepo.findByResolvedFalseAndLastReviewedDateBeforeAndIdGreaterThanOrderByIdAsc(
				BDDMockito.anyLong(), BDDMockito.anyLong(), BDDMockito.any()))
				.thenReturn(new PageImpl<>(List.of()));
	}

	@Test
	public void testSyncData() throws Exception {
		PullRequest pr = PullRequestTest.buildStandardPR();
		pr.setState(PullRequestState.DECLINED);

		PullRequestContainerEntity mockEntity = BDDMockito.mock(PullRequestContainerEntity.class);
		BDDMockito.when(mockEntity.toPullRequest()).thenReturn(pr);

		ApiIntegrationEntity mockApiEntity = BDDMockito.mock(ApiIntegrationEntity.class);

		BDDMockito.when(mockApiIntegrationService.findByLabel(BDDMockito.any()))
				.thenReturn(mockApiEntity);

		BDDMockito.when(mockPrRepo.findByResolvedFalseAndLastReviewedDateBeforeAndIdGreaterThanOrderByIdAsc(
				BDDMockito.anyLong(), BDDMockito.anyLong(), BDDMockito.any()))
				.thenReturn(new PageImpl<PullRequestContainerEntity>(Arrays.asList(mockEntity)));

		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockApi.updatePRData(BDDMockito.any())).thenReturn(pr);
		BDDMockito.when(mockApiEntity.createApi()).thenReturn(mockApi);



		prSync.syncData();
		BDDMockito.verify(mockResultService).markPrResolved(BDDMockito.any());
		Assertions.assertTrue(logWatcher.getMessages().get(1).contains("1 initially"));
		Assertions.assertTrue(logWatcher.getMessages().get(1).contains("1 resolved"));
		BDDMockito.verify(mockSyncSettingsService).recordSyncCompleted(BDDMockito.anyLong());
	}

	@Test
	public void testSyncDataResolvesMergedPullRequest() throws Exception {
		// A merged PR is finished and must leave the unresolved set. If it does not, this
		// sync re-fetches it from Bitbucket on every run, forever, and the unresolved set
		// grows without bound.
		PullRequest pr = PullRequestTest.buildStandardPR();
		pr.setState(PullRequestState.MERGED);

		PullRequestContainerEntity mockEntity = BDDMockito.mock(PullRequestContainerEntity.class);
		BDDMockito.when(mockEntity.toPullRequest()).thenReturn(pr);

		ApiIntegrationEntity mockApiEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(mockApiIntegrationService.findByLabel(BDDMockito.any()))
				.thenReturn(mockApiEntity);

		BDDMockito.when(mockPrRepo.findByResolvedFalseAndLastReviewedDateBeforeAndIdGreaterThanOrderByIdAsc(
				BDDMockito.anyLong(), BDDMockito.anyLong(), BDDMockito.any()))
				.thenReturn(new PageImpl<PullRequestContainerEntity>(Arrays.asList(mockEntity)));

		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockApi.updatePRData(BDDMockito.any())).thenReturn(pr);
		BDDMockito.when(mockApiEntity.createApi()).thenReturn(mockApi);

		prSync.syncData();

		BDDMockito.verify(mockResultService).markPrResolved(BDDMockito.any());
	}

	@Test
	public void testSyncDataLeavesActivePullRequestUnresolved() throws Exception {
		PullRequest pr = PullRequestTest.buildStandardPR();
		pr.setState(PullRequestState.ACTIVE);

		PullRequestContainerEntity mockEntity = BDDMockito.mock(PullRequestContainerEntity.class);
		BDDMockito.when(mockEntity.toPullRequest()).thenReturn(pr);

		ApiIntegrationEntity mockApiEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(mockApiIntegrationService.findByLabel(BDDMockito.any()))
				.thenReturn(mockApiEntity);

		BDDMockito.when(mockPrRepo.findByResolvedFalseAndLastReviewedDateBeforeAndIdGreaterThanOrderByIdAsc(
				BDDMockito.anyLong(), BDDMockito.anyLong(), BDDMockito.any()))
				.thenReturn(new PageImpl<PullRequestContainerEntity>(Arrays.asList(mockEntity)));

		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockApi.updatePRData(BDDMockito.any())).thenReturn(pr);
		BDDMockito.when(mockApiEntity.createApi()).thenReturn(mockApi);

		prSync.syncData();

		// An open PR still has work outstanding, so it stays in the unresolved set.
		BDDMockito.verify(mockResultService, BDDMockito.never())
				.markPrResolved(BDDMockito.any());
	}

	@Test
	public void testMissingPullRequestIsClosedRatherThanRetriedForever() throws Exception {
		// A PR the SCM 404s can never sync. Leaving it unresolved cost one Bitbucket call
		// every cycle, forever - 315 of 315 rows failed this way on the first deploy.
		PullRequest pr = PullRequestTest.buildStandardPR();

		PullRequestContainerEntity mockEntity = BDDMockito.mock(PullRequestContainerEntity.class);
		BDDMockito.when(mockEntity.toPullRequest()).thenReturn(pr);

		ApiIntegrationEntity mockApiEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(mockApiIntegrationService.findByLabel(BDDMockito.any()))
				.thenReturn(mockApiEntity);
		BDDMockito.when(mockPrRepo.findByResolvedFalseAndLastReviewedDateBeforeAndIdGreaterThanOrderByIdAsc(
				BDDMockito.anyLong(), BDDMockito.anyLong(), BDDMockito.any()))
				.thenReturn(new PageImpl<PullRequestContainerEntity>(Arrays.asList(mockEntity)));

		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockApi.updatePRData(BDDMockito.any()))
				.thenThrow(new PullRequestNotFoundException("no such Pull Request"));
		BDDMockito.when(mockApiEntity.createApi()).thenReturn(mockApi);

		prSync.syncData();

		// Closed out, so the next cycle does not re-fetch it.
		BDDMockito.verify(mockResultService).markPrResolved(BDDMockito.any());
	}

	@Test
	public void testStaleApiLabelIsClosedWithoutCallingTheScm() throws Exception {
		// Even the last deleted integration in an inactive repo must be closed out.
		PullRequest pr = PullRequestTest.buildStandardPR();

		PullRequestContainerEntity mockEntity = BDDMockito.mock(PullRequestContainerEntity.class);
		BDDMockito.when(mockEntity.toPullRequest()).thenReturn(pr);
		BDDMockito.when(mockEntity.getApiLabel()).thenReturn(pr.getApiLabel());
		BDDMockito.when(mockEntity.getRepoName()).thenReturn(pr.getRepoName());

		RepositoryEntity staleRepo = BDDMockito.mock(RepositoryEntity.class);
		BDDMockito.when(staleRepo.getApiLabel()).thenReturn(pr.getApiLabel());
		BDDMockito.when(staleRepo.getRepoName()).thenReturn(pr.getRepoName());
		BDDMockito.when(mockRepoRepo.findByLastReviewedDateBefore(BDDMockito.anyLong()))
				.thenReturn(List.of(staleRepo));
		BDDMockito.when(mockApiIntegrationService.findByLabel(BDDMockito.any())).thenReturn(null);
		BDDMockito.when(mockPrRepo.findByResolvedFalseAndLastReviewedDateBeforeAndIdGreaterThanOrderByIdAsc(
				BDDMockito.anyLong(), BDDMockito.anyLong(), BDDMockito.any()))
				.thenReturn(new PageImpl<PullRequestContainerEntity>(Arrays.asList(mockEntity)));

		prSync.syncData();

		BDDMockito.verify(mockResultService).markPrResolved(BDDMockito.any());
		BDDMockito.verify(mockApiIntegrationService).findByLabel(pr.getApiLabel());
	}

	@Test
	public void testTransientFailureIsLeftForTheNextCycle() throws Exception {
		// A timeout or rate limit must NOT close the PR out - that would discard work that
		// would have succeeded shortly after.
		PullRequest pr = PullRequestTest.buildStandardPR();

		PullRequestContainerEntity mockEntity = BDDMockito.mock(PullRequestContainerEntity.class);
		BDDMockito.when(mockEntity.toPullRequest()).thenReturn(pr);

		ApiIntegrationEntity mockApiEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(mockApiIntegrationService.findByLabel(BDDMockito.any()))
				.thenReturn(mockApiEntity);
		BDDMockito.when(mockPrRepo.findByResolvedFalseAndLastReviewedDateBeforeAndIdGreaterThanOrderByIdAsc(
				BDDMockito.anyLong(), BDDMockito.anyLong(), BDDMockito.any()))
				.thenReturn(new PageImpl<PullRequestContainerEntity>(Arrays.asList(mockEntity)));

		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockApi.updatePRData(BDDMockito.any()))
				.thenThrow(new ScanRejectedException("Could not fill all PR Data"));
		BDDMockito.when(mockApiEntity.createApi()).thenReturn(mockApi);

		prSync.syncData();

		BDDMockito.verify(mockResultService, BDDMockito.never())
				.markPrResolved(BDDMockito.any());
	}

	@Test
	public void testSyncDataScanRejectedException() throws Exception {
		PullRequest mockPr = BDDMockito.mock(PullRequest.class);
		BDDMockito.when(mockPr.getState()).thenReturn(PullRequestState.DECLINED);

		PullRequestContainerEntity mockEntity = BDDMockito.mock(PullRequestContainerEntity.class);
		BDDMockito.when(mockEntity.toPullRequest()).thenReturn(mockPr);

		ApiIntegrationEntity mockApiEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(mockApiIntegrationService.findByLabel(BDDMockito.any()))
				.thenReturn(mockApiEntity);
		BDDMockito.when(mockPrRepo.findByResolvedFalseAndLastReviewedDateBeforeAndIdGreaterThanOrderByIdAsc(
				BDDMockito.anyLong(), BDDMockito.anyLong(), BDDMockito.any()))
				.thenReturn(new PageImpl<PullRequestContainerEntity>(Arrays.asList(mockEntity)));

		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockApi.updatePRData(BDDMockito.any()))
				.thenThrow(ScanRejectedException.class);
		BDDMockito.when(mockApiEntity.createApi()).thenReturn(mockApi);

		prSync.syncData();

		List<String> messages = logWatcher.getMessages();
		Assertions.assertEquals(3, messages.size());
		Assertions.assertTrue(messages.get(1).contains("Could not sync PR data"));
	}

	@Test
	public void testOneBadRowDoesNotStopTheSync() throws Exception {
		// Duplicate rows for wt-test #42 made markPrResolved throw. The exception escaped,
		// so later PRs were never synced and the sync was never recorded as complete.
		PullRequest bad = PullRequestTest.buildStandardPR();
		PullRequest good = PullRequestTest.buildStandardPR();
		PullRequestContainerEntity badEntity = BDDMockito.mock(PullRequestContainerEntity.class);
		PullRequestContainerEntity goodEntity = BDDMockito.mock(PullRequestContainerEntity.class);
		BDDMockito.when(badEntity.toPullRequest()).thenReturn(bad);
		BDDMockito.when(goodEntity.toPullRequest()).thenReturn(good);
		BDDMockito.when(mockApiIntegrationService.findByLabel(BDDMockito.any())).thenReturn(null);
		BDDMockito.doThrow(new IllegalStateException("2 results were returned"))
				.doNothing()
				.when(mockResultService).markPrResolved(BDDMockito.any());
		BDDMockito.when(mockPrRepo.findByResolvedFalseAndLastReviewedDateBeforeAndIdGreaterThanOrderByIdAsc(
				BDDMockito.anyLong(), BDDMockito.anyLong(), BDDMockito.any()))
				.thenReturn(new PageImpl<PullRequestContainerEntity>(
						Arrays.asList(badEntity, goodEntity)));

		prSync.syncData();

		BDDMockito.verify(mockResultService, BDDMockito.times(2)).markPrResolved(BDDMockito.any());
		BDDMockito.verify(mockSyncSettingsService).recordSyncCompleted(BDDMockito.anyLong());
		String summary = logWatcher.getMessages().get(logWatcher.getMessages().size() - 1);
		Assertions.assertTrue(summary.contains("1 closed as unsyncable"), summary);
		Assertions.assertTrue(summary.contains("1 failed to sync"), summary);
	}

	@Test
	public void testSyncDataUnknownApiLabel() throws Exception {
		PullRequest pr = PullRequestTest.buildStandardPR();

		PullRequestContainerEntity mockEntity = BDDMockito.mock(PullRequestContainerEntity.class);
		BDDMockito.when(mockEntity.toPullRequest()).thenReturn(pr);

		ApiIntegrationEntity mockApiEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		// The label on this PR no longer matches any registered API integration
		BDDMockito.when(mockApiIntegrationService.findByLabel(BDDMockito.any()))
				.thenReturn(null);

		BDDMockito.when(mockPrRepo.findByResolvedFalseAndLastReviewedDateBeforeAndIdGreaterThanOrderByIdAsc(
				BDDMockito.anyLong(), BDDMockito.anyLong(), BDDMockito.any()))
				.thenReturn(new PageImpl<PullRequestContainerEntity>(Arrays.asList(mockEntity)));

		prSync.syncData();

		// Behaviour changed with item 5.3. A PR whose API integration no longer exists
		// used to be counted as "failed to sync" and retried on every cycle forever.
		// It is now closed out once, because no future cycle can do anything with it.
		List<String> messages = logWatcher.getMessages();
		Assertions.assertEquals(3, messages.size());
		Assertions.assertTrue(messages.get(1).contains("as unsyncable"));
		Assertions.assertTrue(messages.get(1).contains("no longer exists"));
		Assertions.assertTrue(messages.get(2).contains("1 closed as unsyncable"));
		Assertions.assertTrue(messages.get(2).contains("0 failed to sync"));
		BDDMockito.verify(mockResultService).markPrResolved(BDDMockito.any());
	}

	@Test
	public void testSyncDataSkipsWhenNotYetDue() throws Exception {
		// If the configured interval has not elapsed since the last completed sync, no work
		// should happen at all - not even repository selection.
		PullRequestSyncSettingsEntity settings = new PullRequestSyncSettingsEntity();
		settings.setSyncFrequencyHours(24);
		settings.setLastSyncCompletedAt(System.currentTimeMillis());
		BDDMockito.when(mockSyncSettingsService.getSettings()).thenReturn(settings);

		prSync.syncData();

		BDDMockito.verifyNoInteractions(mockPrRepo, mockApiIntegrationService, mockRepoRepo);
		BDDMockito.verify(mockSyncSettingsService, BDDMockito.never())
				.recordSyncCompleted(BDDMockito.anyLong());
	}

	@Test
	public void testSyncDataRunsWhenIntervalElapsed() throws Exception {
		PullRequestSyncSettingsEntity settings = new PullRequestSyncSettingsEntity();
		settings.setSyncFrequencyHours(24);
		settings.setLastSyncCompletedAt(
				System.currentTimeMillis() - java.util.concurrent.TimeUnit.HOURS.toMillis(25));
		BDDMockito.when(mockSyncSettingsService.getSettings()).thenReturn(settings);


		prSync.syncData();

		BDDMockito.verify(mockPrRepo).findByResolvedFalseAndLastReviewedDateBeforeAndIdGreaterThanOrderByIdAsc(
				BDDMockito.anyLong(), BDDMockito.eq(0L), BDDMockito.any());
		BDDMockito.verify(mockSyncSettingsService).recordSyncCompleted(BDDMockito.anyLong());
	}

	@Test
	public void testSyncDataSkipsPullRequestsInInactiveRepos() throws Exception {
		PullRequest pr = PullRequestTest.buildStandardPR();

		PullRequestContainerEntity mockEntity = BDDMockito.mock(PullRequestContainerEntity.class);
		BDDMockito.when(mockEntity.toPullRequest()).thenReturn(pr);
		BDDMockito.when(mockEntity.getApiLabel()).thenReturn(pr.getApiLabel());
		BDDMockito.when(mockEntity.getRepoName()).thenReturn(pr.getRepoName());

		ApiIntegrationEntity mockApiEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(mockApiIntegrationService.findByLabel(pr.getApiLabel())).thenReturn(mockApiEntity);

		BDDMockito.when(mockPrRepo.findByResolvedFalseAndLastReviewedDateBeforeAndIdGreaterThanOrderByIdAsc(
				BDDMockito.anyLong(), BDDMockito.anyLong(), BDDMockito.any()))
				.thenReturn(new PageImpl<PullRequestContainerEntity>(Arrays.asList(mockEntity)));

		RepositoryEntity staleRepo = BDDMockito.mock(RepositoryEntity.class);
		BDDMockito.when(staleRepo.getApiLabel()).thenReturn(pr.getApiLabel());
		BDDMockito.when(staleRepo.getRepoName()).thenReturn(pr.getRepoName());
		BDDMockito.when(mockRepoRepo.findByLastReviewedDateBefore(BDDMockito.anyLong()))
				.thenReturn(Arrays.asList(staleRepo));

		prSync.syncData();

		// Integration existence is checked, but inactive repositories make no SCM call.
		BDDMockito.verify(mockApiIntegrationService).findByLabel(pr.getApiLabel());
		BDDMockito.verify(mockApiEntity, BDDMockito.never()).createApi();
		Assertions.assertTrue(logWatcher.getMessages().get(1).contains("1 skipped (repo inactive"));
	}


	private long reviewCutoffUsedFor(PullRequestSyncSettingsEntity settings) {
		BDDMockito.when(mockSyncSettingsService.getSettings()).thenReturn(settings);
		long before = System.currentTimeMillis();
		prSync.syncData();
		org.mockito.ArgumentCaptor<Long> cutoff = org.mockito.ArgumentCaptor.forClass(Long.class);
		BDDMockito.verify(mockPrRepo).findByResolvedFalseAndLastReviewedDateBeforeAndIdGreaterThanOrderByIdAsc(
				cutoff.capture(), BDDMockito.anyLong(), BDDMockito.any());
		return before - cutoff.getValue();
	}

	@Test
	public void testAFrequentSyncChecksPullRequestsReviewedMoreThanOneIntervalAgo() {
		// With a 15 minute sync a pull request reviewed 20 minutes ago is checked: open pull requests are
		// usually merged within hours, so the old six hour skip would never reach them.
		PullRequestSyncSettingsEntity settings = new PullRequestSyncSettingsEntity();
		settings.setSyncFrequencyMinutes(15);
		long skipWindow = reviewCutoffUsedFor(settings);
		Assertions.assertTrue(Math.abs(skipWindow - 15 * 60_000L) < 5_000L, "skip window " + skipWindow);
	}

	@Test
	public void testALongSyncIntervalKeepsTheSixHourSkip() {
		PullRequestSyncSettingsEntity settings = new PullRequestSyncSettingsEntity();
		settings.setSyncFrequencyHours(24);
		long skipWindow = reviewCutoffUsedFor(settings);
		Assertions.assertTrue(Math.abs(skipWindow - 6 * 3_600_000L) < 5_000L, "skip window " + skipWindow);
	}

	@Test
	public void testTheSyncRunsAgainOnlyAfterTheConfiguredMinutes() {
		PullRequestSyncSettingsEntity settings = new PullRequestSyncSettingsEntity();
		settings.setSyncFrequencyMinutes(15);
		settings.setLastSyncCompletedAt(System.currentTimeMillis() - 10 * 60_000L);
		BDDMockito.when(mockSyncSettingsService.getSettings()).thenReturn(settings);
		prSync.syncData();
		BDDMockito.verify(mockPrRepo, BDDMockito.never())
				.findByResolvedFalseAndLastReviewedDateBeforeAndIdGreaterThanOrderByIdAsc(
						BDDMockito.anyLong(), BDDMockito.anyLong(), BDDMockito.any());

		settings.setLastSyncCompletedAt(System.currentTimeMillis() - 16 * 60_000L);
		prSync.syncData();
		BDDMockito.verify(mockPrRepo).findByResolvedFalseAndLastReviewedDateBeforeAndIdGreaterThanOrderByIdAsc(
				BDDMockito.anyLong(), BDDMockito.anyLong(), BDDMockito.any());
	}
}
