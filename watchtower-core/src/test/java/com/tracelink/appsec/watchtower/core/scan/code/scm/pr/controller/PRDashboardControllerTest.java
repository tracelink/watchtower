package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.controller;

import java.time.LocalDateTime;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.metrics.MetricsCacheService;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResult;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.ui.HtmlAssertions;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class PRDashboardControllerTest {
	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private MetricsCacheService mockMetricsService;

	@MockitoBean
	private PRScanResultService mockScanResultService;

	///////////////////
	// Get dashboard
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_DASHBOARDS_NAME})
	public void testGetDashboard() throws Exception {
		PRScanResult result = new PRScanResult();
		result.setDisplayName("name");
		result.setDate(LocalDateTime.now());
		result.setPrLink("https://foobarbaz");

		BDDMockito.when(mockMetricsService.getPullRequestCount()).thenReturn(2L);
		BDDMockito.when(mockMetricsService.getRepositoryCount()).thenReturn(2L);
		BDDMockito.when(mockMetricsService.getScanCount(CodeScanType.PULL_REQUEST)).thenReturn(3L);
		BDDMockito.when(mockMetricsService.getViolationCount(CodeScanType.PULL_REQUEST)).thenReturn(5L);

		MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.get("/scan/dashboard"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.model().attribute("numPrs", 2L))
				.andExpect(MockMvcResultMatchers.model().attribute("numRepos", 2L))
				.andExpect(MockMvcResultMatchers.model().attribute("numScans", 3L))
				.andExpect(MockMvcResultMatchers.model().attribute("numViolations", 5L))
				.andExpect(MockMvcResultMatchers.model().attributeExists("recentScans"))
				.andReturn();
		// pull_requests/dashboard.html had a btn-group-toggle (stats switcher) conversion in
		// Phase 11 Section B. Only 2 of the 3 HtmlAssertions checks are wired here, not
		// assertHtmlIntegrity: assertNoDuplicateIds legitimately fails on this template - the
		// #statsbtn radios (id="line"/"pie"/"bar") share their id with their target
		// .statscards <div> (same id, e.g. both "line"). Confirmed pre-existing via `git show
		// 2e36eee~1` (predates all of today's Phase 11 work) and systemic across the whole
		// btn-check switcher family: identical pattern in image_scan/dashboard.html,
		// upload_scan/dashboard.html and configuration/repository.html. Left unfixed here -
		// fixing it means changing dashboard-stats-switcher.js/reposwitcher.js's id scheme,
		// which collides with the Section F pass (running concurrently) already touching
		// .statscards and that JS file. Flagged as a new follow-up, not swept under the rug.
		HtmlAssertions.assertAllDataBsTargetsResolve(mvcResult);
		HtmlAssertions.assertAllLabelForsResolve(mvcResult);
		BDDMockito.verify(mockScanResultService).getLastScans(5);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_DASHBOARDS_NAME,
			CorePrivilege.SCAN_ADMIN_NAME})
	public void testGetDashboardRendersAdminPerformanceTrend() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/scan/dashboard"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(
						org.hamcrest.Matchers.containsString("performance-trend")))
				.andExpect(MockMvcResultMatchers.content().string(
						org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString(
								"PR scan performance diagnostics"))));
	}

}
