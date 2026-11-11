package com.tracelink.appsec.watchtower.core.rest.scan.image;

import com.tracelink.appsec.watchtower.core.mvc.PagedResult;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageScanResult;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageScanResultTest;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageScanResultService;

import net.minidev.json.JSONObject;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class ImageScanResultControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private ImageScanResultService resultService;

	private final ObjectMapper objectMapper = new ObjectMapper()
			.registerModule(new JavaTimeModule())
			.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void getResults() throws Exception {
		ImageScanResult result = ImageScanResultTest.buildStandardResult();
		List<ImageScanResult> results = Arrays.asList(result);

		BDDMockito.when(resultService.getScanResultsWithFilters(BDDMockito.any(),
				BDDMockito.anyInt(), BDDMockito.anyInt())).thenReturn(new PagedResult<>(results, false));

		JSONObject json = new JSONObject();
		json.put("results", results);
		String jsonString = objectMapper.writeValueAsString(json);

		mockMvc.perform(MockMvcRequestBuilders
				.get("/rest/imagescan/result"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content().json(jsonString));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void getResultsMultiPage() throws Exception {
		ImageScanResult result = ImageScanResultTest.buildStandardResult();
		// 10 to trigger the next page item
		List<ImageScanResult> results =
				Arrays.asList(result, result, result, result, result, result, result,
						result, result, result);

		BDDMockito.when(resultService.getScanResultsWithFilters(BDDMockito.any(),
				BDDMockito.anyInt(), BDDMockito.anyInt())).thenReturn(new PagedResult<>(results, false));

		JSONObject json = new JSONObject();
		json.put("results", results);
		json.put("next", "http://localhost/rest/imagescan/result/all/1");
		String jsonString = objectMapper.writeValueAsString(json);

		mockMvc.perform(MockMvcRequestBuilders
				.get("/rest/imagescan/result"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content().json(jsonString));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testGetResultForAccountRepoTag() throws Exception {
		ImageScanResult result = ImageScanResultTest.buildStandardResult();

		BDDMockito.when(resultService.generateResultForAccountRepoTag(BDDMockito.anyString(),
				BDDMockito.anyString(), BDDMockito.anyString())).thenReturn(result);

		String jsonString = objectMapper.writeValueAsString(result);

		mockMvc.perform(MockMvcRequestBuilders
				.get("/rest/imagescan/result")
				.param("account", "account").param("repo", "repo").param("tag", "tag"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content().json(jsonString));
	}
}
