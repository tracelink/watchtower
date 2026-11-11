package com.tracelink.appsec.watchtower.core.scan.code.upload.controller;

import java.util.List;
import java.util.Map;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
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
import com.tracelink.appsec.watchtower.core.feedback.FindingFeedbackService;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.result.UploadScanResultViolation;
import com.tracelink.appsec.watchtower.core.scan.presentation.FindingPresentationModel;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanContainerEntity;
import com.tracelink.appsec.watchtower.core.ui.HtmlAssertions;
import com.tracelink.appsec.watchtower.core.scan.code.upload.result.UploadScanResult;
import com.tracelink.appsec.watchtower.core.scan.code.upload.service.UploadScanResultService;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class UploadReportControllerTest {
	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private UploadScanResultService mockScanResultService;

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testGetUploadReport() throws Exception {
		String ticket = "ticket";

		UploadScanResult result = BDDMockito.mock(UploadScanResult.class);

		BDDMockito.when(mockScanResultService.findUploadScanByTicket(ticket))
				.thenReturn(new UploadScanContainerEntity());
		BDDMockito.when(mockScanResultService.generateResultForTicket(ticket)).thenReturn(result);

		MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.get("/uploadscan/report/" + ticket))
				.andExpect(MockMvcResultMatchers.model().attribute("result", result))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(mvcResult);
	}

	@MockitoBean
	private FindingFeedbackService mockFeedback;

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void aSavedReviewJudgmentIsShownOnTheUploadReport() throws Exception {
		UploadScanEntity scan = BDDMockito.mock(UploadScanEntity.class);
		BDDMockito.when(scan.getId()).thenReturn(11L);
		UploadScanContainerEntity container = BDDMockito.mock(UploadScanContainerEntity.class);
		BDDMockito.when(container.getLatestUploadScan()).thenReturn(scan);
		UploadScanResultViolation reviewed = violation(5L);
		UploadScanResultViolation unreviewed = violation(6L);
		UploadScanResult result = BDDMockito.mock(UploadScanResult.class);
		BDDMockito.when(result.getViolations()).thenReturn(List.of(reviewed, unreviewed));
		BDDMockito.when(mockScanResultService.findUploadScanByTicket("t")).thenReturn(container);
		BDDMockito.when(mockScanResultService.generateResultForTicket("t")).thenReturn(result);
		BDDMockito.when(mockFeedback.judgmentsByKey("upload", 11L))
				.thenReturn(Map.of("5", "FALSE_POSITIVE"));

		MvcResult mvcResult = mockMvc.perform(MockMvcRequestBuilders.get("/uploadscan/report/t"))
				.andReturn();

		@SuppressWarnings("unchecked")
		List<FindingPresentationModel> findings = (List<FindingPresentationModel>) mvcResult
				.getModelAndView().getModel().get("findings");
		Assertions.assertEquals("false", findings.get(0).getReviewState());
		Assertions.assertEquals("unreviewed", findings.get(1).getReviewState());
	}

	private static UploadScanResultViolation violation(long id) {
		UploadScanResultViolation violation = new UploadScanResultViolation();
		violation.setViolationId(id);
		violation.setViolationName("rule-" + id);
		violation.setFileName("a.txt");
		violation.setSeverity("High");
		return violation;
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
