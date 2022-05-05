package com.tracelink.appsec.watchtower.core.rest.scan.image;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageScanResult;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageScanResultTest;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageScanResultService;
import java.util.Arrays;
import java.util.List;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class ImageScanResultControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private ImageScanResultService resultService;

	@Autowired
	private MappingJackson2HttpMessageConverter springMvcJacksonConverter;

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void getResults() throws Exception {
		ImageScanResult result = ImageScanResultTest.buildStandardResult();
		List<ImageScanResult> results = Arrays.asList(result);

		BDDMockito.when(resultService.getScanResultsWithFilters(BDDMockito.any(),
				BDDMockito.anyInt(), BDDMockito.anyInt())).thenReturn(results);

		JSONObject json = new JSONObject();
		json.put("results", results);
		String jsonString = springMvcJacksonConverter.getObjectMapper().writeValueAsString(json);

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
				BDDMockito.anyInt(), BDDMockito.anyInt())).thenReturn(results);

		JSONObject json = new JSONObject();
		json.put("results", results);
		json.put("next", "http://localhost/rest/imagescan/result/all/1");
		String jsonString = springMvcJacksonConverter.getObjectMapper().writeValueAsString(json);

		mockMvc.perform(MockMvcRequestBuilders
				.get("/rest/imagescan/result"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content().json(jsonString));
	}
}
