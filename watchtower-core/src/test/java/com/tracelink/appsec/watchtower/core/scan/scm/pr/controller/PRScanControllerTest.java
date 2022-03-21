package com.tracelink.appsec.watchtower.core.scan.scm.pr.controller;

import java.util.ArrayList;
import java.util.List;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.scm.ScmApiType;
import com.tracelink.appsec.watchtower.core.scan.scm.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.scm.ScmFactoryService;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.service.PRScanningService;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class PRScanControllerTest {
	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private PRScanningService mockScanService;

	@MockBean
	private PRScanResultService mockScanResultService;

	@MockBean
	private ScmFactoryService mockScannerFactory;

	///////////////////
	// Get scan
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_SUBMIT_NAME})
	public void testScanGet() throws Exception {
		long inQueue = 1L;
		long active = 2L;
		boolean paused = false;
		boolean quiesced = false;
		List<PullRequestScanEntity> sri = new ArrayList<>();

		BDDMockito.when(mockScanService.getTaskNumInQueue())
				.thenReturn(inQueue);
		BDDMockito.when(mockScanService.getTaskNumActive()).thenReturn(active);
		BDDMockito.when(mockScanService.isPaused()).thenReturn(paused);
		BDDMockito.when(mockScanService.isQuiesced()).thenReturn(quiesced);
		BDDMockito.when(mockScanResultService.getLastScans(BDDMockito.anyInt())).thenReturn(sri);

		mockMvc.perform(MockMvcRequestBuilders.get("/scan"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.model().attribute("numScansQueued",
						Matchers.is(inQueue)))
				.andExpect(MockMvcResultMatchers.model().attribute("numScansInProgress",
						Matchers.is(active)))
				.andExpect(MockMvcResultMatchers.model().attribute("scanStatePaused",
						Matchers.is(paused)))
				.andExpect(MockMvcResultMatchers.model().attribute("scanStateQuiesced",
						Matchers.is(quiesced)))
				.andExpect(
						MockMvcResultMatchers.model().attribute("lastScans", Matchers.is(sri)));
	}

	///////////////////
	// Post scan
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_SUBMIT_NAME})
	public void testScanSubmit() throws Exception {
		ArgumentCaptor<PullRequest> prCaptor = ArgumentCaptor.forClass(PullRequest.class);
		String prid = "213";
		String repo = "repo";
		String apiLabel = "myLabel";

		IScmApi mockApi = BDDMockito.mock(IScmApi.class);
		BDDMockito.when(mockScannerFactory.createApiForApiEntity(BDDMockito.any()))
				.thenReturn(mockApi);

		BDDMockito.when(mockApi.updatePRData(BDDMockito.any())).thenAnswer(e -> e.getArgument(0));

		mockMvc.perform(MockMvcRequestBuilders.post("/scan").param("prid", prid).param("repo", repo)
				.param("apiLabel", apiLabel)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						Matchers.is("Successfully Queued Scan")));

		BDDMockito.verify(mockScanService).doPullRequestScan(prCaptor.capture());
		PullRequest pr = prCaptor.getValue();
		Assertions.assertEquals(prid, pr.getPrId());
		Assertions.assertEquals(repo, pr.getRepoName());
		Assertions.assertEquals(apiLabel, pr.getApiLabel());
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_SUBMIT_NAME})
	public void testScanSubmitFailure() throws Exception {
		String message = "Error";
		BDDMockito.willThrow(new ScanRejectedException(message)).given(mockScanService)
				.doPullRequestScan(BDDMockito.any());
		String prid = "213";
		String repo = "repo";
		String type = ScmApiType.BITBUCKET_CLOUD.getTypeName();

		mockMvc.perform(MockMvcRequestBuilders.post("/scan").param("prid", prid).param("repo", repo)
				.param("type", type)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString(message)));
	}

	///////////////////
	// Pause scan
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_ADMIN_NAME})
	public void testScanPause() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/scan/pause").param("pause", "true")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection());
		BDDMockito.verify(mockScanService).pauseExecution();
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_ADMIN_NAME})
	public void testScanUnPause() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/scan/pause").param("pause", "false")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection());
		BDDMockito.verify(mockScanService).resumeExecution();
	}

	///////////////////
	// Queue scan
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_ADMIN_NAME})
	public void testScanQuiesce() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/scan/quiesce").param("quiesce", "true")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection());
		BDDMockito.verify(mockScanService).quiesce();
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_ADMIN_NAME})
	public void testScanUnQuiesce() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/scan/quiesce").param("quiesce", "false")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection());
		BDDMockito.verify(mockScanService).unQuiesce();
	}

}
