package com.tracelink.appsec.watchtower.core.scan.code.upload.controller;

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
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanContainerEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.result.UploadScanResult;
import com.tracelink.appsec.watchtower.core.scan.code.upload.service.UploadScanResultService;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class UploadReportControllerTest {
	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private UploadScanResultService mockScanResultService;

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testGetUploadReport() throws Exception {
		String ticket = "ticket";

		UploadScanResult result = BDDMockito.mock(UploadScanResult.class);

		BDDMockito.when(mockScanResultService.findUploadScanByTicket(ticket))
				.thenReturn(new UploadScanContainerEntity());
		BDDMockito.when(mockScanResultService.generateResultForTicket(ticket)).thenReturn(result);

		mockMvc.perform(MockMvcRequestBuilders.get("/uploadscan/report/" + ticket))
				.andExpect(MockMvcResultMatchers.model().attribute("result", result));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testGetUploadReportUnknown() throws Exception {
		String ticket = "ticket";

		BDDMockito.when(mockScanResultService.findUploadScanByTicket(ticket))
				.thenReturn(null);

		mockMvc.perform(MockMvcRequestBuilders.get("/uploadscan/report/" + ticket))
				.andExpect(MockMvcResultMatchers.model().attribute("result",
						Matchers.emptyOrNullString()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION, "Unknown ticket"))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/uploadscan"));
	}
}
