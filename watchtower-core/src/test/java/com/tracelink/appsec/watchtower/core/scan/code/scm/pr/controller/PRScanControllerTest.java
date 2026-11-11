package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.controller;

import java.util.ArrayList;
import java.util.List;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.exception.ScanRejectedException;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PRScanSubmitResult;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanningService;
import com.tracelink.appsec.watchtower.core.ui.HtmlAssertions;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class PRScanControllerTest {
	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private PRScanningService mockScanService;

	@MockitoBean
	private PRScanResultService mockScanResultService;

	@MockitoBean
	private com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService mockApiIntegrationService;

	@MockitoBean
	private com.tracelink.appsec.watchtower.core.scan.repository.RepositoryService mockRepositoryService;

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

		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/scan"))
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
						MockMvcResultMatchers.model().attribute("lastScans", Matchers.is(sri)))
				.andExpect(MockMvcResultMatchers.model().attribute("scripts",
						Matchers.hasItem("/scripts/scan-submission.js")))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_SUBMIT_NAME, CorePrivilege.SCAN_RESULTS_NAME})
	public void testRecentScansCountFindingsWithoutMcrMatches() throws Exception {
		var container = new com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestContainerEntity();
		container.setRepoName("payments-api");
		container.setPrId("7");
		var scan = new PullRequestScanEntity();
		scan.setContainer(container);
		scan.setStatus(com.tracelink.appsec.watchtower.core.scan.ScanStatus.DONE);
		scan.setStartDate(1_000L);
		scan.setEndDate(2_000L);
		org.springframework.test.util.ReflectionTestUtils.setField(scan, "id", 42L);
		var finding = new com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity();
		finding.setViolationName("Hard-coded token");
		finding.setSeverity(com.tracelink.appsec.watchtower.core.rule.RulePriority.HIGH);
		var mcr = new com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity();
		mcr.setViolationName("MCR Match: Crypto review");
		mcr.setSeverity(com.tracelink.appsec.watchtower.core.rule.RulePriority.INFORMATIONAL);
		org.springframework.test.util.ReflectionTestUtils.setField(scan, "violations", new ArrayList<>(List.of(finding, mcr)));
		BDDMockito.when(mockScanResultService.getLastScans(BDDMockito.anyInt())).thenReturn(List.of(scan));

		mockMvc.perform(MockMvcRequestBuilders.get("/scan"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("1 manual code review match, not counted in findings")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("/scan/mcr/report/42")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("<strong class=\"wt-num\">1</strong>")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("The pull request is still open")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.not(Matchers.containsString("wt-sev-6"))));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_SUBMIT_NAME})
	public void repositorySuggestionsComeFromTheChosenPullRequestIntegration() throws Exception {
		var bitbucket = BDDMockito.mock(com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity.class);
		BDDMockito.when(bitbucket.getApiLabel()).thenReturn("BitBucket");
		BDDMockito.when(bitbucket.getScanType()).thenReturn(com.tracelink.appsec.watchtower.core.scan.code.CodeScanType.PULL_REQUEST);
		BDDMockito.when(mockApiIntegrationService.getAllSettings()).thenReturn(List.of(bitbucket));
		var repo = new com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity();
		repo.setRepoName("wt-test");
		repo.setEnabled(true);
		BDDMockito.when(mockRepositoryService.list(BDDMockito.any(), BDDMockito.eq("BitBucket"), BDDMockito.any(), BDDMockito.any()))
				.thenReturn(new org.springframework.data.domain.PageImpl<>(List.of(repo)));

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/repositories").param("apiLabel", "BitBucket").param("q", "wt-"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.jsonPath("$[0].name").value("wt-test"))
				.andExpect(MockMvcResultMatchers.jsonPath("$[0].status").value("Active"));
		// An integration that isn't a configured pull request source lists nothing.
		mockMvc.perform(MockMvcRequestBuilders.get("/scan/repositories").param("apiLabel", "Other").param("q", "wt-"))
				.andExpect(MockMvcResultMatchers.jsonPath("$").isEmpty());
	}

	///////////////////
	// Post scan
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_SUBMIT_NAME})
	public void testScanSubmit() throws Exception {
		BDDMockito.when(mockScanService.doPullRequestScan(BDDMockito.any()))
				.thenReturn(PRScanSubmitResult.QUEUED);
		ArgumentCaptor<PullRequest> prCaptor = ArgumentCaptor.forClass(PullRequest.class);
		String prid = "213";
		String repo = "repo";
		String apiLabel = "myLabel";

		IScmApi mockApi = BDDMockito.mock(IScmApi.class);

		BDDMockito.when(mockApi.updatePRData(BDDMockito.any())).thenAnswer(e -> e.getArgument(0));

		mockMvc.perform(MockMvcRequestBuilders.post("/scan").param("prid", prid).param("repo", repo)
				.param("apiLabel", apiLabel)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						Matchers.is(PRScanSubmitResult.QUEUED.getDescription())));

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
		String type = ApiType.BITBUCKET_CLOUD.getTypeName();

		mockMvc.perform(MockMvcRequestBuilders.post("/scan").param("prid", prid).param("repo", repo)
				.param("type", type)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString(message)));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_SUBMIT_NAME})
	public void testScanSubmitRefusesAPullRequestThatDoesNotExistAndDoesNotQueueIt()
			throws Exception {
		BDDMockito.willThrow(
				new com.tracelink.appsec.watchtower.core.exception.PullRequestNotFoundException(
						"Pull request not found"))
				.given(mockScanService).requirePullRequestExists(BDDMockito.any());

		mockMvc.perform(MockMvcRequestBuilders.post("/scan").param("prid", "999999")
				.param("repo", "wt-test").param("apiLabel", "myLabel")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("Pull request not found")));
		BDDMockito.verify(mockScanService, BDDMockito.never()).doPullRequestScan(BDDMockito.any());
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_SUBMIT_NAME})
	public void testScanSubmitWithoutAPullRequestNumberIsRefusedNotQueued() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/scan").param("prid", "  ")
				.param("repo", "wt-test").param("apiLabel", "myLabel")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("pull request number")));
		BDDMockito.verify(mockScanService, BDDMockito.never()).requirePullRequestExists(BDDMockito.any());
		BDDMockito.verify(mockScanService, BDDMockito.never()).doPullRequestScan(BDDMockito.any());
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_SUBMIT_NAME})
	public void testScanSubmitWithoutARepositoryIsRefusedNotQueued() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/scan").param("prid", "5")
				.param("apiLabel", "myLabel").with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("repository")));
		BDDMockito.verify(mockScanService, BDDMockito.never()).doPullRequestScan(BDDMockito.any());
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
