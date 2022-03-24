package com.tracelink.appsec.watchtower.core.scan.code.upload.controller;

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
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.ScanType;
import com.tracelink.appsec.watchtower.core.scan.code.upload.service.UploadScanResultService;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class UploadDashboardControllerTest {
	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private MetricsCacheService mockMetricsService;

	@MockBean
	private UploadScanResultService mockScanResultService;

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_DASHBOARDS_NAME})
	public void testGetDashboard() throws Exception {
		BDDMockito.when(mockMetricsService.isMetricsCacheReady()).thenReturn(true);
		BDDMockito.when(mockMetricsService.getScanCount(ScanType.UPLOAD)).thenReturn(3L);
		BDDMockito.when(mockMetricsService.getViolationCount(ScanType.UPLOAD)).thenReturn(5L);
		BDDMockito.when(mockMetricsService.getAverageScanTimeString(ScanType.UPLOAD))
				.thenReturn("7");

		mockMvc.perform(MockMvcRequestBuilders.get("/uploadscan/dashboard"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.model().attribute("numScans", 3L))
				.andExpect(MockMvcResultMatchers.model().attribute("numViolations", 5L))
				.andExpect(MockMvcResultMatchers.model().attribute("avgScanTime", "7"));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_DASHBOARDS_NAME})
	public void testGetDashboardMetricsNotReady() throws Exception {
		BDDMockito.when(mockMetricsService.isMetricsCacheReady()).thenReturn(false);
		BDDMockito.when(mockMetricsService.getScanCount(ScanType.UPLOAD)).thenReturn(3L);
		BDDMockito.when(mockMetricsService.getViolationCount(ScanType.UPLOAD)).thenReturn(5L);
		BDDMockito.when(mockMetricsService.getAverageScanTimeString(ScanType.UPLOAD))
				.thenReturn("7");

		mockMvc.perform(MockMvcRequestBuilders.get("/uploadscan/dashboard"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.model().attribute("numScans", 3L))
				.andExpect(MockMvcResultMatchers.model().attribute("numViolations", 5L))
				.andExpect(MockMvcResultMatchers.model().attribute("avgScanTime", "7"))
				.andExpect(MockMvcResultMatchers.model().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						MetricsCacheService.METRICS_NOT_READY));
	}
}
