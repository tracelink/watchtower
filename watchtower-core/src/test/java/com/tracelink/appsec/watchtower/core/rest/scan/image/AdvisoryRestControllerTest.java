package com.tracelink.appsec.watchtower.core.rest.scan.image;

import java.util.Arrays;

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
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.scan.image.entity.AdvisoryEntity;
import com.tracelink.appsec.watchtower.core.scan.image.entity.AdvisoryEntityTest;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageAdvisoryService;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;


@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class AdvisoryRestControllerTest {
	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private ImageAdvisoryService imageAdvisoryService;

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testGetAllAdvisories() throws Exception {
		long total = 6;
		AdvisoryEntity advisory = AdvisoryEntityTest.buildStandardAdvisory();

		JSONArray array = new JSONArray();
		array.add(advisory);

		JSONObject json = new JSONObject();
		json.put("total", total);
		json.put("advisories", array);

		BDDMockito.when(imageAdvisoryService.getTotalNumberAdvisories()).thenReturn(total);

		BDDMockito.when(imageAdvisoryService.getAllAdvisories())
				.thenReturn(Arrays.asList(advisory));

		mockMvc.perform(MockMvcRequestBuilders
				.get("/rest/advisory"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content().json(json.toJSONString()));
	}


	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_RESULTS_NAME})
	public void testSearchAdvisoriesReturnsOnePageWithTotal() throws Exception {
		AdvisoryEntity advisory = AdvisoryEntityTest.buildStandardAdvisory();
		BDDMockito.when(imageAdvisoryService.search("openssl", 7.0, "score", 1, 25))
				.thenReturn(new com.tracelink.appsec.watchtower.core.scan.image.service.ImageAdvisoryService.AdvisoryPage(
						Arrays.asList(advisory), 26, 1, 25));
		BDDMockito.when(imageAdvisoryService.search("", 0, "bogus", 0, 25))
				.thenThrow(new IllegalArgumentException("Check the search, score, sort and page"));

		mockMvc.perform(MockMvcRequestBuilders.get("/rest/advisory/search").param("search", "openssl")
				.param("minScore", "7").param("page", "1"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.jsonPath("$.total").value(26))
				.andExpect(MockMvcResultMatchers.jsonPath("$.advisories[0].advisoryName").value(advisory.getAdvisoryName()));
		mockMvc.perform(MockMvcRequestBuilders.get("/rest/advisory/search").param("sort", "bogus"))
				.andExpect(MockMvcResultMatchers.status().isBadRequest());
	}
}
