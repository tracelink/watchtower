package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.BDDMockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.core.env.Environment;
import org.springframework.data.domain.PageImpl;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.logging.CoreLogWatchExtension;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestState;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestTest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRContainerRepository;

@ExtendWith(SpringExtension.class)
public class PullRequestSynchronizerTest {


	@RegisterExtension
	public CoreLogWatchExtension logWatcher =
			CoreLogWatchExtension.forClass(PullRequestSynchronizer.class);

	@MockBean
	private PRContainerRepository mockPrRepo;

	@MockBean
	private Environment mockEnvironment;

	@MockBean
	private PRScanResultService mockResultService;

	@MockBean
	private ApiIntegrationService mockApiIntegrationService;

	private PullRequestSynchronizer prSync;

	@BeforeEach
	public void setup() {
		prSync = new PullRequestSynchronizer(mockEnvironment, mockPrRepo, mockResultService,
				mockApiIntegrationService);
	}

	@Test
	public void testSyncData() throws Exception {
		PullRequest pr = PullRequestTest.buildStandardPR();
		pr.setState(PullRequestState.DECLINED);

		PullRequestContainerEntity mockEntity = BDDMockito.mock(PullRequestContainerEntity.class);
		BDDMockito.when(mockEntity.toPullRequest()).thenReturn(pr);

		ApiIntegrationEntity mockApiEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(mockApiIntegrationService.getAllSettings())
				.thenReturn(Arrays.asList(mockApiEntity));

		BDDMockito.when(mockApiIntegrationService.findByLabel(BDDMockito.any()))
				.thenReturn(mockApiEntity);

		BDDMockito.when(mockPrRepo.findByResolvedFalse(BDDMockito.any()))
				.thenReturn(new PageImpl<PullRequestContainerEntity>(Arrays.asList(mockEntity)));

		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockApi.updatePRData(BDDMockito.any())).thenReturn(pr);
		BDDMockito.when(mockApiEntity.createApi()).thenReturn(mockApi);



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

		ApiIntegrationEntity mockApiEntity = BDDMockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(mockApiIntegrationService.getAllSettings())
				.thenReturn(Arrays.asList(mockApiEntity));
		BDDMockito.when(mockApiIntegrationService.findByLabel(BDDMockito.any()))
				.thenReturn(mockApiEntity);
		BDDMockito.when(mockPrRepo.findByResolvedFalse(BDDMockito.any()))
				.thenReturn(new PageImpl<PullRequestContainerEntity>(Arrays.asList(mockEntity)));

		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockApi.updatePRData(BDDMockito.any()))
				.thenThrow(ScanRejectedException.class);
		BDDMockito.when(mockApiEntity.createApi()).thenReturn(mockApi);

		prSync.syncData();

		List<String> messages = logWatcher.getMessages();
		Assertions.assertEquals(3, messages.size());
		Assertions.assertTrue(messages.get(1).contains("Error while creating api for data sync"));
	}

}
