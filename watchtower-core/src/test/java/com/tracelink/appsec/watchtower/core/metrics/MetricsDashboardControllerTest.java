package com.tracelink.appsec.watchtower.core.metrics;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.data.util.Pair;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.ui.HtmlAssertions;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class MetricsDashboardControllerTest {
	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private MetricsCacheService mockMetricsService;

	@MockitoBean
	private HomeDashboardService mockHomeDashboardService;

	@Autowired
	private com.tracelink.appsec.watchtower.core.scan.queue.PRScanWorkItemRepository workItems;

	private HomeOverviewModel overview;

	@BeforeEach
	void setUpHomeOverview() {
		overview = new HomeOverviewModel(12, 2, 8, "1.20 s");
		BDDMockito.when(mockHomeDashboardService.getOverview()).thenReturn(overview);
		BDDMockito.when(mockHomeDashboardService.getRecentActivity()).thenReturn(java.util.List.of());
		BDDMockito.when(mockHomeDashboardService.getProcessorHealth()).thenReturn(
				new ProcessorHealthModel("Processors available", "success", "check_circle", 0, 0));
	}

	///////////////////
	// Get dashboard
	///////////////////
	@Test
	@WithMockUser
	public void testGetDashboard() throws Exception {
		long scanCount = 1;
		long violationCount = 213;
		String scanTime = "DateString";
		long scanCountToday = 1;

		BDDMockito.when(mockMetricsService.isMetricsCacheReady()).thenReturn(true);

		BDDMockito.when(mockMetricsService.getScanCount(BDDMockito.any())).thenReturn(scanCount);
		BDDMockito.when(mockMetricsService.getViolationCount(BDDMockito.any()))
				.thenReturn(violationCount);
		BDDMockito.when(mockMetricsService.getAverageScanTimeString(BDDMockito.any()))
				.thenReturn(scanTime);
		BDDMockito.when(mockMetricsService.getScanCountToday(BDDMockito.any()))
				.thenReturn(scanCountToday);
		BDDMockito.when(mockMetricsService.getAverageSourceSizeString(BDDMockito.any()))
				.thenReturn("100.00 KB");

		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				// has metrics object
				.andExpect(MockMvcResultMatchers.model().attribute("metrics", Matchers.allOf(
						// with the right keys (each scan type display name)
						// Matchers.hasKey(ScanType.PULL_REQUEST.getDisplayName()),
						// Matchers.hasKey(ScanType.UPLOAD.getDisplayName()),
						// and the scan type metrics are the correct pairs
						Matchers.hasEntry(Matchers.is(CodeScanType.PULL_REQUEST.getDisplayName()),
								Matchers.allOf(
										Matchers.hasItem(Pair.of("Scans Completed",
												String.valueOf(scanCount))),
										Matchers.hasItem(Pair.of("Violations Found",
												String.valueOf(violationCount))),
										Matchers.hasItem(Pair.of("Average Scan Time",
												scanTime)),
										Matchers.hasItem(Pair.of("Scans Today",
												String.valueOf(scanCountToday))))))))
				.andExpect(MockMvcResultMatchers.model().attribute("overview", overview))
				.andExpect(MockMvcResultMatchers.model().attribute("recentActivity",
						Matchers.empty()))
				.andExpect(MockMvcResultMatchers.model().attribute("homeTotals", Matchers.hasItem(
						new HomeTotal("Pull requests", "compare_arrows", scanCount, violationCount,
								"/scan/dashboard", "/scan/results/all", "/scan"))))
				.andExpect(MockMvcResultMatchers.content().string(
						Matchers.containsString("Total scans")))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
	}

	@Test
	@WithMockUser(authorities = {"Rule Modify", "Scan Results View"})
	public void ruleWorkTilesShowForPeopleWhoCanOpenRuleWork() throws Exception {
		BDDMockito.when(mockMetricsService.getAverageScanTimeString(BDDMockito.any())).thenReturn("");
		BDDMockito.when(mockMetricsService.getAverageSourceSizeString(BDDMockito.any())).thenReturn("");
		mockMvc.perform(MockMvcRequestBuilders.get("/"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.model().attribute("workTiles", Matchers.hasSize(5)))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("Needs a person")));
	}

	@Test
	@WithMockUser
	public void ruleWorkTilesHiddenWithoutRuleAccess() throws Exception {
		BDDMockito.when(mockMetricsService.getAverageScanTimeString(BDDMockito.any())).thenReturn("");
		BDDMockito.when(mockMetricsService.getAverageSourceSizeString(BDDMockito.any())).thenReturn("");
		mockMvc.perform(MockMvcRequestBuilders.get("/"))
				.andExpect(MockMvcResultMatchers.model().attribute("workTiles", Matchers.empty()))
				.andExpect(MockMvcResultMatchers.content().string(
						Matchers.not(Matchers.containsString("Needs a person"))));
	}

	@Test
	@WithMockUser
	public void testLayoutShellCarriesHxBoost() throws Exception {
		// IMPROVEMENT_PLAN.md item 9.1 acceptance criteria: pin that the shared layout
		// shell (fragments/container.html) still boosts navigation, so a future edit to
		// that fragment can't silently drop it.
		BDDMockito.when(mockMetricsService.isMetricsCacheReady()).thenReturn(true);
		BDDMockito.when(mockMetricsService.getScanCount(BDDMockito.any())).thenReturn(1L);
		BDDMockito.when(mockMetricsService.getViolationCount(BDDMockito.any())).thenReturn(1L);
		BDDMockito.when(mockMetricsService.getAverageScanTimeString(BDDMockito.any()))
				.thenReturn("DateString");
		BDDMockito.when(mockMetricsService.getScanCountToday(BDDMockito.any())).thenReturn(1L);
		BDDMockito.when(mockMetricsService.getAverageSourceSizeString(BDDMockito.any()))
				.thenReturn("100.00 KB");

		mockMvc.perform(MockMvcRequestBuilders.get("/"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("hx-boost=\"true\"")))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("id=\"content\"")));
	}

	@Test
	@WithMockUser
	public void testMetricsNotReady() throws Exception {
		BDDMockito.when(mockMetricsService.isMetricsCacheReady()).thenReturn(false);
		BDDMockito.when(mockMetricsService.getAverageScanTimeString(BDDMockito.any()))
				.thenReturn("");
		BDDMockito.when(mockMetricsService.getAverageSourceSizeString(BDDMockito.any()))
				.thenReturn("");
		mockMvc.perform(MockMvcRequestBuilders.get("/"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.model().attribute("metricsStale", true))
				.andExpect(MockMvcResultMatchers.model().attributeDoesNotExist(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION));
	}


	@Test
	@WithMockUser(authorities = {"PR Settings Modify"})
	public void dismissingARequestThatIsGoneSaysSoAndReturnsToTheReferringPage() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/scan-workload/987654/dismiss")
				.header("Referer", "http://localhost/scan/dashboard")
				.with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors
						.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.redirectedUrl("/scan/dashboard"))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						"That request is no longer in the list"));
	}

	@Test
	@WithMockUser(authorities = {"PR Settings Modify"})
	public void dismissNeverRedirectsToAnotherSite() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/scan-workload/987654/dismiss")
				.header("Referer", "https://evil.example/steal")
				.with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors
						.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.redirectedUrl("/"));
	}

	@Test
	@WithMockUser
	public void dismissNeedsThePrSettingsModifyPrivilege() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.post("/scan-workload/987654/dismiss")
				.with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors
						.csrf()))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
	}

	private com.tracelink.appsec.watchtower.core.scan.queue.PRScanWorkItemEntity savedFailedRequest() {
		var item = new com.tracelink.appsec.watchtower.core.scan.queue.PRScanWorkItemEntity();
		item.setDedupKey("dismiss-test-" + System.nanoTime());
		item.setApiLabel("Bitbucket2");
		item.setRepoName("dismiss-test");
		item.setPrId("1");
		item.setStatus(com.tracelink.appsec.watchtower.core.scan.queue.PRScanWorkItemEntity.WorkStatus.VALIDATION_FAILED);
		item.setFailureReason("Pull request not found");
		item.setEnqueuedAt(System.currentTimeMillis() - 60_000);
		item.setUpdatedAt(System.currentTimeMillis());
		return workItems.saveAndFlush(item);
	}

	@Test
	@WithMockUser(authorities = {"PR Settings Modify"})
	public void aFailedRequestOffersRemovalToWhoMayModifyPrSettings() throws Exception {
		var item = savedFailedRequest();
		try {
			mockMvc.perform(MockMvcRequestBuilders.get("/scan-workload"))
					.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
					.andExpect(MockMvcResultMatchers.content().string(Matchers
							.containsString("/scan-workload/" + item.getId() + "/dismiss")))
					.andExpect(MockMvcResultMatchers.content()
							.string(Matchers.containsString("data-confirm=")));
		} finally {
			workItems.delete(item);
		}
	}

	@Test
	@WithMockUser
	public void aFailedRequestOffersNoRemovalToOthers() throws Exception {
		var item = savedFailedRequest();
		try {
			mockMvc.perform(MockMvcRequestBuilders.get("/scan-workload"))
					.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
					.andExpect(MockMvcResultMatchers.content()
							.string(Matchers.containsString("dismiss-test #1")))
					.andExpect(MockMvcResultMatchers.content()
							.string(Matchers.not(Matchers.containsString("/dismiss"))));
		} finally {
			workItems.delete(item);
		}
	}

	@Test
	@WithMockUser
	public void idleWorkloadIsAChipNotACard() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/scan-workload").param("part", "chip"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("id=\"pr-scan-workload-chip\"")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("Idle")))
				.andExpect(MockMvcResultMatchers.content().string(
						Matchers.not(Matchers.containsString("id=\"pr-scan-workload\""))));
		// The card still answers its own poll, hidden while idle, so it reappears once scans queue.
		mockMvc.perform(MockMvcRequestBuilders.get("/scan-workload").param("part", "anything-else"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("id=\"pr-scan-workload\"")))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("hidden")));
	}

}
