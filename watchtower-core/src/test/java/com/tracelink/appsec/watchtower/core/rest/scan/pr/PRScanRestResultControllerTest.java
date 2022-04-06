package com.tracelink.appsec.watchtower.core.rest.scan.pr;

import java.util.ArrayList;
import java.util.Arrays;

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

	@MockBean
	private PRScanResultService mockScanResultService;

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME}, username = "user")
	public void testScan() throws Exception {
		PRScanResult result = new PRScanResult();
		result.setPrId("foo");

		BDDMockito
				.when(mockScanResultService
						.getScanResultsWithFilters(PRResultFilter.ALL, 10, 0))
				.thenReturn(Arrays.asList(result));

		JSONObject jsonContent = new JSONObject();
		jsonContent.put("next", "http://localhost/rest/scan/result/all/1");
		jsonContent.put("results", Arrays.asList(result));

		mockMvc.perform(MockMvcRequestBuilders.get("/rest/scan/result"))
				.andExpect(MockMvcResultMatchers.content().json(jsonContent.toString()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME}, username = "user")
	public void testScanSpecific() throws Exception {
		PRScanResult result = new PRScanResult();
		result.setPrId("foo");

		BDDMockito
				.when(mockScanResultService
						.getScanResultsWithFilters(PRResultFilter.UNRESOLVED, 10, 1))
				.thenReturn(Arrays.asList(result));

		JSONObject jsonContent = new JSONObject();
		jsonContent.put("next", "http://localhost/rest/scan/result/unresolved/2");
		jsonContent.put("results", Arrays.asList(result));

		mockMvc.perform(MockMvcRequestBuilders
				.get("/rest/scan/result/" + PRResultFilter.UNRESOLVED.getName() + "/1"))
				.andExpect(MockMvcResultMatchers.content().json(jsonContent.toString()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME}, username = "user")
	public void testScanEnd() throws Exception {
		BDDMockito
				.when(mockScanResultService
						.getScanResultsWithFilters(PRResultFilter.UNRESOLVED, 10, 1))
				.thenReturn(new ArrayList<>());

		JSONObject jsonContent = new JSONObject();
		jsonContent.put("results", new ArrayList<>());

		mockMvc.perform(MockMvcRequestBuilders
				.get("/rest/scan/result/" + PRResultFilter.UNRESOLVED.getName() + "/1"))
				.andExpect(MockMvcResultMatchers.content().json(jsonContent.toString()));
	}
}
