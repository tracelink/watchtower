package com.tracelink.appsec.watchtower.core.rest.scan.image;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageResultFilter;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageScanResult;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageScanResultService;
import java.util.ArrayList;
import java.util.Arrays;
import net.minidev.json.JSONObject;
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


@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class ImageScanRestResultControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private ImageScanResultService mockScanResultService;

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME}, username = "user")
	public void testResult() throws Exception {
		ImageScanResult result = new ImageScanResult();
		result.setApiLabel("foo");

		BDDMockito
				.when(mockScanResultService
						.getScanResultsWithFilters(ImageResultFilter.ALL, 10, 0))
				.thenReturn(Arrays.asList(result));

		JSONObject jsonContent = new JSONObject();
		jsonContent.put("next", "http://localhost/rest/imagescan/result/all/1");
		jsonContent.put("results", Arrays.asList(result));

		mockMvc.perform(MockMvcRequestBuilders.get("/rest/imagescan/result"))
				.andExpect(MockMvcResultMatchers.content().json(jsonContent.toString()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME}, username = "user")
	public void testResultSpecific() throws Exception {
		ImageScanResult result = new ImageScanResult();
		result.setApiLabel("foo");

		BDDMockito
				.when(mockScanResultService
						.getScanResultsWithFilters(ImageResultFilter.VIOLATIONS, 10, 1))
				.thenReturn(Arrays.asList(result));

		JSONObject jsonContent = new JSONObject();
		jsonContent.put("next", "http://localhost/rest/imagescan/result/violations/2");
		jsonContent.put("results", Arrays.asList(result));

		mockMvc.perform(MockMvcRequestBuilders
				.get("/rest/imagescan/result/" + ImageResultFilter.VIOLATIONS.getName() + "/1"))
				.andExpect(MockMvcResultMatchers.content().json(jsonContent.toString()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME}, username = "user")
	public void testResultEnd() throws Exception {
		BDDMockito
				.when(mockScanResultService
						.getScanResultsWithFilters(ImageResultFilter.VIOLATIONS, 10, 1))
				.thenReturn(new ArrayList<>());

		JSONObject jsonContent = new JSONObject();
		jsonContent.put("results", new ArrayList<>());

		mockMvc.perform(MockMvcRequestBuilders
				.get("/rest/imagescan/result/" + ImageResultFilter.VIOLATIONS.getName() + "/1"))
				.andExpect(MockMvcResultMatchers.content().json(jsonContent.toString()));
	}
}
