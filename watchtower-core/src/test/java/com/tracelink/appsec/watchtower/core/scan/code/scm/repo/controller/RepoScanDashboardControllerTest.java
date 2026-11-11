package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.controller;

import java.util.List;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.metrics.MetricsCacheService;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.RepoScanViewService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.SeverityCounts;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryInventoryService;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryInventoryService.Coverage;
import com.tracelink.appsec.watchtower.core.ui.HtmlAssertions;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class RepoScanDashboardControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private MetricsCacheService metrics;

	@MockitoBean
	private RepoScanViewService views;

	@MockitoBean
	private RepositoryInventoryService inventory;

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_DASHBOARDS_NAME,
			CorePrivilege.SCAN_RESULTS_NAME})
	public void dashboardShowsRepositoryMetricsAndRecentScans() throws Exception {
		BDDMockito.when(metrics.isMetricsCacheReady()).thenReturn(true);
		BDDMockito.when(metrics.getScanCount(CodeScanType.REPOSITORY)).thenReturn(3L);
		BDDMockito.when(metrics.getViolationCount(CodeScanType.REPOSITORY)).thenReturn(5L);
		BDDMockito.when(metrics.getAverageScanTimeString(CodeScanType.REPOSITORY))
				.thenReturn("7 s");
		BDDMockito.when(views.latestFinished(5)).thenReturn(List.of(scan()));
		BDDMockito.when(inventory.coverage(CodeScanType.PULL_REQUEST))
				.thenReturn(new Coverage(40, 30, 6));

		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/reposcan/dashboard"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.model().attribute("numScans", 3L))
				.andExpect(MockMvcResultMatchers.model().attribute("numViolations", 5L))
				.andExpect(MockMvcResultMatchers.model().attribute("avgScanTime", "7 s"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("Top rules"),
						Matchers.containsString("payments-api@main"),
						Matchers.containsString("/reposcan/report/0"),
						Matchers.containsString("/scripts/dashboard/repo-dashboard.js"),
						Matchers.containsString("Five most recent repository scans"),
						Matchers.containsString("data-repo-coverage"),
						Matchers.containsString(">75%<"),
						Matchers.containsString("/repositories?scanned=never"),
						Matchers.containsString("href=\"/repositories/0?view=all\""))))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_DASHBOARDS_NAME)
	public void dashboardSaysWhenMetricsAreNotReady() throws Exception {
		BDDMockito.when(metrics.isMetricsCacheReady()).thenReturn(false);
		mockMvc.perform(MockMvcRequestBuilders.get("/reposcan/dashboard"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.model().attribute("metricsReady", false))
				.andExpect(MockMvcResultMatchers.content().string(
						Matchers.containsString("Preparing metrics")));
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.SCAN_RESULTS_NAME)
	public void dashboardNeedsTheDashboardPrivilege() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/reposcan/dashboard"))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
	}

	private static RepoScanEntity scan() {
		RepositoryEntity repo = new RepositoryEntity();
		repo.setRepoName("payments-api");
		RepoScanEntity scan = new RepoScanEntity();
		scan.setRepository(repo);
		scan.setBranch("main");
		scan.setStatus(ScanStatus.DONE);
		scan.setStartDate(1_000L);
		scan.setEndDate(3_000L);
		scan.setSeverityCounts(SeverityCounts.of(List.of(RulePriority.HIGH)));
		return scan;
	}
}
