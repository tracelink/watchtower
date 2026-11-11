package com.tracelink.appsec.watchtower.core.scan.image.controller;

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
import com.tracelink.appsec.watchtower.core.metrics.MetricsCacheService;
import com.tracelink.appsec.watchtower.core.ui.HtmlAssertions;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanType;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageScanResultService;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class ImageScanDashboardControllerTest {
	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private MetricsCacheService metricsService;

	@MockitoBean
	private ImageScanResultService scanResultService;

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_DASHBOARDS_NAME})
	public void testGetDashboardNotReady() throws Exception {
		long scans = 123L;
		long vios = 234L;
		String time = "1 hour";
		BDDMockito.when(metricsService.isMetricsCacheReady()).thenReturn(false);
		BDDMockito.when(metricsService.getScanCount(ImageScanType.CONTAINER)).thenReturn(scans);
		BDDMockito.when(metricsService.getViolationCount(ImageScanType.CONTAINER)).thenReturn(vios);
		BDDMockito.when(metricsService.getAverageScanTimeString(ImageScanType.CONTAINER))
				.thenReturn(time);

		mockMvc.perform(MockMvcRequestBuilders.get("/imagescan/dashboard"))
				.andExpect(MockMvcResultMatchers.model().attribute("numScans", Matchers.is(scans)))
				.andExpect(
						MockMvcResultMatchers.model().attribute("numViolations", Matchers.is(vios)))
				.andExpect(
						MockMvcResultMatchers.model().attribute("avgScanTime", Matchers.is(time)))
				.andExpect(MockMvcResultMatchers.model().attributeExists("recentScans"))
				.andExpect(MockMvcResultMatchers.model().attribute("scripts", Matchers.hasSize(5)))
				.andExpect(MockMvcResultMatchers.model().attribute("metricsReady", false))
				.andExpect(MockMvcResultMatchers.model().attributeDoesNotExist(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION));

	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_DASHBOARDS_NAME})
	public void testGetDashboardReady() throws Exception {
		long scans = 123L;
		long vios = 234L;
		String time = "1 hour";
		BDDMockito.when(metricsService.isMetricsCacheReady()).thenReturn(true);
		BDDMockito.when(metricsService.getScanCount(ImageScanType.CONTAINER)).thenReturn(scans);
		BDDMockito.when(metricsService.getViolationCount(ImageScanType.CONTAINER)).thenReturn(vios);
		BDDMockito.when(metricsService.getAverageScanTimeString(ImageScanType.CONTAINER))
				.thenReturn(time);

		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/imagescan/dashboard"))
				.andExpect(MockMvcResultMatchers.model().attribute("numScans", Matchers.is(scans)))
				.andExpect(
						MockMvcResultMatchers.model().attribute("numViolations", Matchers.is(vios)))
				.andExpect(
						MockMvcResultMatchers.model().attribute("avgScanTime", Matchers.is(time)))
				.andExpect(MockMvcResultMatchers.model().attribute("scripts", Matchers.hasSize(5)))
				.andExpect(MockMvcResultMatchers.model().attributeDoesNotExist(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
		BDDMockito.verify(scanResultService).getLastScans(5);
	}
}
