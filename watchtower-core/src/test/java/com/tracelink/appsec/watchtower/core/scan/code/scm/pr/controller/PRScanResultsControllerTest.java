package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.controller;

import java.util.Arrays;

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
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRResultFilter;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResult;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PRScanResultService;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class PRScanResultsControllerTest {
	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private PRScanResultService mockScanResultService;

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testGetFilterPage() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/scan/results"))
				.andExpect(MockMvcResultMatchers.model().attribute("filters",
						PRResultFilter.values()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testGetResultsForFilter() throws Exception {
		int pageNum = 0;
		String filter = "all";
		PRScanResult result = BDDMockito.mock(PRScanResult.class);

		BDDMockito
				.when(mockScanResultService.getScanResultsWithFilters(BDDMockito.any(),
						BDDMockito.anyInt(), BDDMockito.anyInt()))
				.thenReturn(Arrays.asList(result));

		mockMvc.perform(
				MockMvcRequestBuilders.get("/scan/results/" + filter).param("page",
						String.valueOf(pageNum)))
				.andExpect(MockMvcResultMatchers.model().attribute("filters",
						PRResultFilter.values()))
				.andExpect(MockMvcResultMatchers.model().attribute("activeFilter", filter))
				.andExpect(MockMvcResultMatchers.model().attribute("activePageNum", pageNum))
				.andExpect(MockMvcResultMatchers.model().attribute("results",
						Matchers.contains(result)));
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
						MockMvcResultMatchers.redirectedUrl("/scan/results/" + filter + "?page=0"));
	}
}
