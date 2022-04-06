package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.controller;

import java.util.concurrent.RejectedExecutionException;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.APIIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.APIIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.bb.BBCloudIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.bb.BBPullRequestTest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequestState;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanningService;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class PRScanRestControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private PRScanningService mockScanService;

	@MockBean
	private PRScanResultService mockResultService;


	@MockBean
	private APIIntegrationService mockApiService;

	@Test
	public void testScanPRSuccess() throws Exception {
		APIIntegrationEntity apiEntity = new BBCloudIntegrationEntity();
		String prJSON = BBPullRequestTest.buildStandardJSONString();
		String apiLabel = "apiLabel";
		PullRequest pr = new PullRequest(apiLabel);
		pr.setState(PullRequestState.ACTIVE);
		BDDMockito.when(mockApiService.findByLabel(apiLabel)).thenReturn(apiEntity);

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/scan/" + apiLabel)
				.contentType(MediaType.APPLICATION_JSON)
				.content(prJSON)).andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.is("Added scan successfully")));

		BDDMockito.verify(mockScanService).doPullRequestScan(pr);
	}

	@Test
	public void testScanPRFailure() throws Exception {
		String type = ApiType.BITBUCKET_CLOUD.getTypeName();
		BDDMockito.willThrow(RejectedExecutionException.class).given(mockScanService)
				.doPullRequestScan(BDDMockito.any());
		BDDMockito.when(mockApiService.findByLabel(type))
				.thenReturn(BDDMockito.mock(APIIntegrationEntity.class));

		String prJSON = BBPullRequestTest.buildStandardJSONString();

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/scan/" + type)
				.contentType(MediaType.APPLICATION_JSON)
				.content(prJSON)).andExpect(MockMvcResultMatchers.status().is4xxClientError())
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("Error adding the scan")));
	}

	@Test
	public void testResolveOnDeclinedPr() throws Exception {
		APIIntegrationEntity apiEntity = new BBCloudIntegrationEntity();
		String prJSON = BBPullRequestTest.buildJSON().toString();
		String apiLabel = "apiLabel";
		PullRequest pr = new PullRequest(apiLabel);
		pr.setState(PullRequestState.DECLINED);
		BDDMockito.when(mockApiService.findByLabel(apiLabel)).thenReturn(apiEntity);

		mockMvc.perform(MockMvcRequestBuilders.post("/rest/scan/" + apiLabel)
				.contentType(MediaType.APPLICATION_JSON)
				.content(prJSON.toString()))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("PR already declined")));

		BDDMockito.verify(mockScanService, BDDMockito.never()).doPullRequestScan(BDDMockito.any());
		BDDMockito.verify(mockResultService).markPrResolved(pr);
	}

}
