package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.controller;

import com.tracelink.appsec.watchtower.core.mvc.PagedResult;
import java.util.Arrays;
import java.util.List;

import org.hamcrest.Matchers;
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
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.mergegate.MergeGateOutcome;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.mergegate.MergeGateReport;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.mergegate.MergeGateService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRResultFilter;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRResultTab;
import com.tracelink.appsec.watchtower.core.ui.HtmlAssertions;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRResultPeriod;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResult;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class PRScanResultsControllerTest {
	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private PRScanResultService mockScanResultService;

	@MockitoBean
	private MergeGateService mockMergeGateService;

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testGetFilterPage() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/scan/results"))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/scan/results/all"));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testGetResultsForFilter() throws Exception {
		int pageNum = 0;
		String filter = "all";
		PRScanResult result = BDDMockito.mock(PRScanResult.class);

		BDDMockito
				.when(mockScanResultService.getScanResultsWithFilters(BDDMockito.any(),
						BDDMockito.any(PRResultPeriod.class), BDDMockito.anyInt(),
						BDDMockito.anyInt()))
				.thenReturn(new PagedResult<>(Arrays.asList(result), false));

		mockMvc.perform(
				MockMvcRequestBuilders.get("/scan/results/" + filter).param("page",
						String.valueOf(pageNum)))
				.andExpect(MockMvcResultMatchers.model().attribute("filters",
						PRResultTab.all()))
				.andExpect(MockMvcResultMatchers.model().attribute("activeFilter", filter))
				.andExpect(MockMvcResultMatchers.model().attribute("activePageNum", pageNum))
				.andExpect(MockMvcResultMatchers.model().attribute("results",
						Matchers.contains(result)));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testEmptyFilterSaysSoInsteadOfAnEmptyTable() throws Exception {
		BDDMockito
				.when(mockScanResultService.getScanResultsWithFilters(BDDMockito.any(),
						BDDMockito.any(PRResultPeriod.class), BDDMockito.anyInt(),
						BDDMockito.anyInt()))
				.thenReturn(new PagedResult<>(java.util.List.of(), false));

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/results/all"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString(
								"No pull request scans match this filter in the last 90 days."),
						Matchers.containsString("Pull request results"),
						Matchers.not(Matchers.containsString("<table")))));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testNextDisabledWhenNoNextPage() throws Exception {
		// Next must be a genuinely disabled non-link once Slice.hasNext() reports there is
		// no further page. Keep this assertion aligned with the shared operations paginator.
		PRScanResult result = BDDMockito.mock(PRScanResult.class);
		BDDMockito
				.when(mockScanResultService.getScanResultsWithFilters(BDDMockito.any(),
						BDDMockito.any(PRResultPeriod.class), BDDMockito.anyInt(),
						BDDMockito.anyInt()))
				.thenReturn(new PagedResult<>(Arrays.asList(result), 1, 1, 2, 2));

		String content = mockMvc.perform(MockMvcRequestBuilders.get("/scan/results/all"))
				.andExpect(MockMvcResultMatchers.model().attribute("hasNext", false))
				.andReturn().getResponse().getContentAsString().replaceAll("\\s+", " ");
		org.hamcrest.MatcherAssert.assertThat(content, Matchers.containsString(
				"class=\"wt-pagination__step is-disabled\" aria-disabled=\"true\">Next"
						+ "<span class=\"material-icons\" aria-hidden=\"true\">"
						+ "chevron_right</span></span>"));
		org.hamcrest.MatcherAssert.assertThat(content, Matchers.not(Matchers.containsString(
				"href=\"/scan/results/all?period=recent&amp;page=1\"")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testSinglePageShowsNoPager() throws Exception {
		// Fixes board (2026-10-22): no "1-1 of 1" pager when there is nothing to page.
		PRScanResult result = BDDMockito.mock(PRScanResult.class);
		BDDMockito
				.when(mockScanResultService.getScanResultsWithFilters(BDDMockito.any(),
						BDDMockito.any(PRResultPeriod.class), BDDMockito.anyInt(),
						BDDMockito.anyInt()))
				.thenReturn(new PagedResult<>(Arrays.asList(result), false));

		String content = mockMvc.perform(MockMvcRequestBuilders.get("/scan/results/all"))
				.andReturn().getResponse().getContentAsString();
		org.hamcrest.MatcherAssert.assertThat(content,
				Matchers.not(Matchers.containsString("wt-pagination__status")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testFindingsShowCountsPerSeverity() throws Exception {
		// Each severity is a coloured count chip ("2H", "1M"), not only the total.
		PRScanResult result = BDDMockito.mock(PRScanResult.class);
		BDDMockito.when(result.getViolations()).thenReturn(Arrays.asList(
				violation(1), violation(1), violation(3)));
		BDDMockito
				.when(mockScanResultService.getScanResultsWithFilters(BDDMockito.any(),
						BDDMockito.any(PRResultPeriod.class), BDDMockito.anyInt(),
						BDDMockito.anyInt()))
				.thenReturn(new PagedResult<>(Arrays.asList(result), false));

		String content = mockMvc.perform(MockMvcRequestBuilders.get("/scan/results/all"))
				.andReturn().getResponse().getContentAsString().replaceAll("\\s+", " ");
		org.hamcrest.MatcherAssert.assertThat(content, Matchers.allOf(
				Matchers.containsString("wt-sev-count wt-sev-1\" aria-label=\"2 High findings\" data-tip=\"2 High findings\">2H"),
				Matchers.containsString("wt-sev-count wt-sev-3\" aria-label=\"1 Medium finding\" data-tip=\"1 Medium finding\">1M")));
	}

	private static com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResultViolation violation(
			int severityValue) {
		var v = new com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResultViolation();
		v.setSeverityValue(severityValue);
		return v;
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testNextEnabledWhenNextPageExists() throws Exception {
		PRScanResult result = BDDMockito.mock(PRScanResult.class);
		BDDMockito
				.when(mockScanResultService.getScanResultsWithFilters(BDDMockito.any(),
						BDDMockito.any(PRResultPeriod.class), BDDMockito.anyInt(),
						BDDMockito.anyInt()))
				.thenReturn(new PagedResult<>(Arrays.asList(result), true));

		String content = mockMvc.perform(MockMvcRequestBuilders.get("/scan/results/all"))
				.andExpect(MockMvcResultMatchers.model().attribute("hasNext", true))
				.andReturn().getResponse().getContentAsString().replaceAll("\\s+", " ");
		org.hamcrest.MatcherAssert.assertThat(content, Matchers.containsString(
				"href=\"/scan/results/all?period=recent&amp;page=1\""));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void theLast90DaysAreTheDefaultAndOlderKeepsItsPeriodInEveryLink() throws Exception {
		PRScanResult result = BDDMockito.mock(PRScanResult.class);
		BDDMockito.when(mockScanResultService.getScanResultsWithFilters(BDDMockito.any(),
				BDDMockito.any(PRResultPeriod.class), BDDMockito.anyInt(), BDDMockito.anyInt()))
				.thenReturn(new PagedResult<>(Arrays.asList(result), true));

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/results/all"));
		BDDMockito.verify(mockScanResultService).getScanResultsWithFilters(PRResultFilter.ALL,
				PRResultPeriod.RECENT, 10, 0);

		String content = mockMvc.perform(MockMvcRequestBuilders.get("/scan/results/violations")
				.param("period", "older"))
				.andExpect(MockMvcResultMatchers.model().attribute("period", PRResultPeriod.OLDER))
				.andReturn().getResponse().getContentAsString().replaceAll("\\s+", " ");
		BDDMockito.verify(mockScanResultService).getScanResultsWithFilters(
				PRResultFilter.VIOLATIONS, PRResultPeriod.OLDER, 10, 0);
		org.hamcrest.MatcherAssert.assertThat(content, Matchers.allOf(
				Matchers.containsString("aria-current=\"page\">Older<"),
				Matchers.containsString("href=\"/scan/results/unresolved?period=older\""),
				Matchers.containsString("href=\"/scan/results/violations?period=older&amp;page=1\""),
				Matchers.containsString("href=\"/scan/results/violations?period=recent\"")));
	}

	private static MergeGateReport mergeGateReport(int days) {
		return new MergeGateReport(days, 0L, 12, 7,
				new MergeGateReport.BeforeScan(3, 1, 1, 0, 1),
				new MergeGateReport.Blocking(2, 1, 1),
				List.of(new MergeGateReport.RepositoryCount("bb", "payments-api", 6, 2, 1, 3)),
				List.of(new MergeGateReport.MergedPullRequestRow("bb", "payments-api", "42",
						"https://bitbucket.org/acme/payments-api/pull-requests/42", 1_000L,
						"0123456789abcdef0123", MergeGateOutcome.SCAN_IN_PROGRESS,
						MergeGateOutcome.SCAN_IN_PROGRESS.getLabel())),
				false);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void theMergeGateTabShowsItsCountsAndTheUngatedMerges() throws Exception {
		BDDMockito.when(mockMergeGateService.report(30)).thenReturn(mergeGateReport(30));

		MvcResult result = mockMvc
				.perform(MockMvcRequestBuilders.get("/scan/results/merge-gate"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.model().attribute("activeFilter", "merge-gate"))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.allOf(
						Matchers.containsString("aria-current=\"page\""), Matchers.containsString(">Merge gate<"),
						Matchers.containsString("12 merges"),
						Matchers.containsString("3 merged before scan"),
						Matchers.containsString("2 with blocking findings"),
						Matchers.containsString(">payments-api #42<"),
						Matchers.containsString(">Scan in progress<"),
						Matchers.containsString(">0123456789ab<"),
						Matchers.containsString("3 of 6"))))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void theMergeGateWindowFallsBackToThirtyDaysForAnUnlistedValue() throws Exception {
		BDDMockito.when(mockMergeGateService.report(BDDMockito.anyInt()))
				.thenAnswer(a -> mergeGateReport(a.getArgument(0)));

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/results/merge-gate").param("days", "7"))
				.andExpect(MockMvcResultMatchers.status().isOk());
		mockMvc.perform(MockMvcRequestBuilders.get("/scan/results/merge-gate").param("days", "x"))
				.andExpect(MockMvcResultMatchers.status().isOk());

		BDDMockito.verify(mockMergeGateService).report(7);
		BDDMockito.verify(mockMergeGateService).report(30);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testGetResultsForUnknownFilter() throws Exception {
		int pageNum = 0;
		String filter = "foo";

		mockMvc.perform(
				MockMvcRequestBuilders.get("/scan/results/" + filter).param("page",
						String.valueOf(pageNum)))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION, "Unknown Filter"));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testGetResultsForNegativePage() throws Exception {
		int pageNum = -1;
		String filter = "all";

		mockMvc.perform(
				MockMvcRequestBuilders.get("/scan/results/" + filter).param("page",
						String.valueOf(pageNum)))
				.andExpect(
						MockMvcResultMatchers.redirectedUrl("/scan/results/" + filter
								+ "?period=recent&page=0"));
	}
}
