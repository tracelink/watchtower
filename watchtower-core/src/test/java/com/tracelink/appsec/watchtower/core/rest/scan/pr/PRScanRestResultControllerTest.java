package com.tracelink.appsec.watchtower.core.rest.scan.pr;

import java.time.LocalDateTime;
import com.tracelink.appsec.watchtower.core.mvc.PagedResult;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

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
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.mergegate.MergeGateOutcome;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.mergegate.MergeGateReport;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.mergegate.MergeGateService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRResultFilter;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResult;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;

import net.minidev.json.JSONObject;


@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class PRScanRestResultControllerTest {
	@Autowired
	private MockMvc mockMvc;

	private final ObjectMapper objectMapper = new ObjectMapper()
			.registerModule(new JavaTimeModule())
			.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

	@MockitoBean
	private PRScanResultService mockScanResultService;

	@MockitoBean
	private MergeGateService mockMergeGateService;

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME}, username = "user")
	public void theMergeGateIsReadableAsJson() throws Exception {
		BDDMockito.when(mockMergeGateService.report(7)).thenReturn(new MergeGateReport(7, 0L, 4,
				2, new MergeGateReport.BeforeScan(1, 0, 0, 0, 1),
				new MergeGateReport.Blocking(1, 0, 1), List.of(),
				List.of(new MergeGateReport.MergedPullRequestRow("bb", "payments-api", "9", null,
						5L, null, MergeGateOutcome.NEVER_SCANNED, "Never scanned")),
				false));

		mockMvc.perform(MockMvcRequestBuilders.get("/rest/scan/result/merge-gate")
				.param("days", "7"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.jsonPath("$.merges").value(4))
				.andExpect(MockMvcResultMatchers.jsonPath("$.mergedBeforeScan.neverScanned").value(1))
				.andExpect(MockMvcResultMatchers.jsonPath("$.mergedWithBlockingFindings.notBypassed")
						.value(1))
				.andExpect(MockMvcResultMatchers.jsonPath("$.pullRequests[0].outcome")
						.value("NEVER_SCANNED"));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME}, username = "user")
	public void aMergeGateWindowOutOfRangeIsABadRequest() throws Exception {
		BDDMockito.when(mockMergeGateService.report(400))
				.thenThrow(new IllegalArgumentException("Choose a window of 1 to 90 days."));

		mockMvc.perform(MockMvcRequestBuilders.get("/rest/scan/result/merge-gate")
				.param("days", "400"))
				.andExpect(MockMvcResultMatchers.status().isBadRequest())
				.andExpect(MockMvcResultMatchers.jsonPath("$.error")
						.value("Choose a window of 1 to 90 days."));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_DASHBOARDS_NAME}, username = "user")
	public void theMergeGateNeedsScanResultsView() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/rest/scan/result/merge-gate"))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
		BDDMockito.verifyNoInteractions(mockMergeGateService);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME}, username = "user")
	public void testResult() throws Exception {
		PRScanResult result = new PRScanResult();
		result.setDate(LocalDateTime.now());
		result.setPrId("foo");

		BDDMockito
				.when(mockScanResultService
						.getScanResultsWithFilters(PRResultFilter.ALL, 10, 0))
				.thenReturn(new PagedResult<>(Arrays.asList(result), false));

		JSONObject jsonContent = new JSONObject();
		jsonContent.put("next", "http://localhost/rest/scan/result/all/1");
		jsonContent.put("results", Arrays.asList(result));

		mockMvc.perform(MockMvcRequestBuilders.get("/rest/scan/result"))
				.andExpect(MockMvcResultMatchers.content().json(objectMapper.writeValueAsString(jsonContent)));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME}, username = "user")
	public void testResultSpecific() throws Exception {
		PRScanResult result = new PRScanResult();
		result.setDate(LocalDateTime.now());
		result.setPrId("foo");

		BDDMockito
				.when(mockScanResultService
						.getScanResultsWithFilters(PRResultFilter.UNRESOLVED, 10, 1))
				.thenReturn(new PagedResult<>(Arrays.asList(result), false));

		JSONObject jsonContent = new JSONObject();
		jsonContent.put("next", "http://localhost/rest/scan/result/unresolved/2");
		jsonContent.put("results", Arrays.asList(result));

		mockMvc.perform(MockMvcRequestBuilders
				.get("/rest/scan/result/" + PRResultFilter.UNRESOLVED.getName() + "/1"))
				.andExpect(MockMvcResultMatchers.content().json(objectMapper.writeValueAsString(jsonContent)));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME}, username = "user")
	public void testResultEnd() throws Exception {
		BDDMockito
				.when(mockScanResultService
						.getScanResultsWithFilters(PRResultFilter.UNRESOLVED, 10, 1))
				.thenReturn(new PagedResult<>(new ArrayList<>(), false));

		JSONObject jsonContent = new JSONObject();
		jsonContent.put("results", new ArrayList<>());

		mockMvc.perform(MockMvcRequestBuilders
				.get("/rest/scan/result/" + PRResultFilter.UNRESOLVED.getName() + "/1"))
				.andExpect(MockMvcResultMatchers.content().json(objectMapper.writeValueAsString(jsonContent)));
	}
}
