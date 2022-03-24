package com.tracelink.appsec.watchtower.core.scan.code.pr.controller;

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
import com.tracelink.appsec.watchtower.core.scan.code.pr.result.PRScanResult;
import com.tracelink.appsec.watchtower.core.scan.code.pr.service.PRScanResultService;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class PRScanReportControllerTest {
	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private PRScanResultService mockScanResultService;

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testGetReport() throws Exception {
		String id = "1";

		PRScanResult result = BDDMockito.mock(PRScanResult.class);

		BDDMockito.when(mockScanResultService.getScanResultForScanId(id)).thenReturn(result);

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/" + id))
				.andExpect(MockMvcResultMatchers.model().attribute("result", result));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testGetReportUnknown() throws Exception {
		String id = "1";

		BDDMockito.when(mockScanResultService.getScanResultForScanId(id))
				.thenReturn(null);

		mockMvc.perform(MockMvcRequestBuilders.get("/scan/report/" + id))
				.andExpect(MockMvcResultMatchers.model().attribute("result",
						Matchers.emptyOrNullString()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION, "Unknown ID"))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/scan"));
	}
}
