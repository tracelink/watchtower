package com.tracelink.appsec.watchtower.core.scan.scm.pr.service;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.BDDMockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.PageImpl;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.logging.CoreLogWatchExtension;
import com.tracelink.appsec.watchtower.core.scan.scm.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.scm.ScmFactoryService;
import com.tracelink.appsec.watchtower.core.scan.scm.api.APIIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.scm.api.APIIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.PullRequestState;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.PullRequestTest;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.repository.PRContainerRepository;

@ExtendWith(SpringExtension.class)
public class PullRequestSynchronizerTest {


	@RegisterExtension
	public CoreLogWatchExtension logWatcher = CoreLogWatchExtension.forClass(PullRequestSynchronizer.class);

	@MockBean
	private PRContainerRepository mockPrRepo;

	@MockBean
	private ScmFactoryService mockScanFactoryService;

	@MockBean
	private PRScanResultService mockResultService;

	@MockBean
	private APIIntegrationService mockApiIntegrationService;

	private PullRequestSynchronizer prSync;

	@BeforeEach
	public void setup() {
		prSync = new PullRequestSynchronizer(mockPrRepo, mockScanFactoryService, mockResultService,
				mockApiIntegrationService);
	}

	@Test
	public void testSyncData() throws Exception {
		PullRequest pr = PullRequestTest.buildStandardPR();
		pr.setState(PullRequestState.DECLINED);

		PullRequestContainerEntity mockEntity = BDDMockito.mock(PullRequestContainerEntity.class);
		BDDMockito.when(mockEntity.toPullRequest()).thenReturn(pr);

		BDDMockito.when(mockApiIntegrationService.getAllSettings())
				.thenReturn(Arrays.asList(BDDMockito.mock(APIIntegrationEntity.class)));
		BDDMockito.when(mockPrRepo.findByResolvedFalse(BDDMockito.any()))
				.thenReturn(new PageImpl<PullRequestContainerEntity>(Arrays.asList(mockEntity)));

		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockApi.updatePRData(BDDMockito.any())).thenReturn(pr);

		BDDMockito.when(mockScanFactoryService.createApiForApiEntity(BDDMockito.any()))
				.thenReturn(mockApi);

		prSync.syncData();
		BDDMockito.verify(mockResultService).markPrResolved(BDDMockito.any());
		Assertions.assertTrue(logWatcher.getMessages().get(1).contains("1 initially"));
		Assertions.assertTrue(logWatcher.getMessages().get(1).contains("1 resolved"));
	}

	@Test
	public void testSyncDataScanRejectedException() throws Exception {
		PullRequest mockPr = BDDMockito.mock(PullRequest.class);
		BDDMockito.when(mockPr.getState()).thenReturn(PullRequestState.DECLINED);

		PullRequestContainerEntity mockEntity = BDDMockito.mock(PullRequestContainerEntity.class);
		BDDMockito.when(mockEntity.toPullRequest()).thenReturn(mockPr);

		BDDMockito.when(mockApiIntegrationService.getAllSettings())
				.thenReturn(Arrays.asList(BDDMockito.mock(APIIntegrationEntity.class)));
		BDDMockito.when(mockPrRepo.findByResolvedFalse(BDDMockito.any()))
				.thenReturn(new PageImpl<PullRequestContainerEntity>(Arrays.asList(mockEntity)));

		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockApi.updatePRData(BDDMockito.any()))
				.thenThrow(ScanRejectedException.class);

		BDDMockito.when(mockScanFactoryService.createApiForApiEntity(BDDMockito.any()))
				.thenReturn(mockApi);

		prSync.syncData();

		List<String> messages = logWatcher.getMessages();
		Assertions.assertEquals(3, messages.size());
		Assertions.assertTrue(messages.get(1).contains("Error while creating api for data sync"));
	}

}
