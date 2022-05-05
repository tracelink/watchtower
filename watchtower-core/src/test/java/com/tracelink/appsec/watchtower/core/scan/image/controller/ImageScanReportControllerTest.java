package com.tracelink.appsec.watchtower.core.scan.image.controller;

import org.hamcrest.Matchers;
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
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageScanEntity;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageScanResult;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageScanResultTest;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageScanResultService;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class ImageScanReportControllerTest {
	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private ImageScanResultService scanResultService;

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testGetImageReportExists() throws Exception {
		ImageScanEntity entity = new ImageScanEntity();
		ImageScanResult result = ImageScanResultTest.buildStandardResult();
		BDDMockito.when(scanResultService.findById(BDDMockito.anyLong())).thenReturn(entity);
		BDDMockito.when(scanResultService.generateResultForScan(entity)).thenReturn(result);

		mockMvc.perform(MockMvcRequestBuilders.get("/imagescan/report/1"))
				.andExpect(MockMvcResultMatchers.model().attribute("result", Matchers.is(result)))
				.andExpect(MockMvcResultMatchers.model().attribute("scripts", Matchers.hasSize(1)));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testGetDashboardReady() throws Exception {
		BDDMockito.when(scanResultService.findById(BDDMockito.anyLong())).thenReturn(null);

		mockMvc.perform(MockMvcRequestBuilders.get("/imagescan/report/1"))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION, Matchers.is("Unknown ID")));
	}
}
