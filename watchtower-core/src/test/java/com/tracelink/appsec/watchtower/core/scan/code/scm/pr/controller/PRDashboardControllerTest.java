package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.controller;

import java.time.LocalDateTime;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.metrics.MetricsCacheService;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResult;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class PRDashboardControllerTest {
	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private MetricsCacheService mockMetricsService;

	@MockBean
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

		BDDMockito.when(mockScanResultService.countPrs()).thenReturn(2L);
		BDDMockito.when(mockScanResultService.countRepos()).thenReturn(2L);
		BDDMockito.when(mockMetricsService.getScanCount(CodeScanType.PULL_REQUEST)).thenReturn(3L);
		BDDMockito.when(mockMetricsService.getViolationCount(CodeScanType.PULL_REQUEST)).thenReturn(5L);

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/dashboard"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.model().attribute("numPrs", 2L))
				.andExpect(MockMvcResultMatchers.model().attribute("numRepos", 2L))
				.andExpect(MockMvcResultMatchers.model().attribute("numScans", 3L))
				.andExpect(MockMvcResultMatchers.model().attribute("numViolations", 5L));
	}

}
