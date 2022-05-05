package com.tracelink.appsec.watchtower.core.rest.scan.image;

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

	@MockBean
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

}
