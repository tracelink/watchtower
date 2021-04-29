package com.tracelink.appsec.watchtower.core.metrics;

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

import net.minidev.json.JSONObject;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class MetricsRestControllerTest {
	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private MetricsCacheService mockMetricsCacheService;

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_DASHBOARDS_NAME})
	public void testGetViolationsByType() throws Exception {
		String key = "test";
		String value = "value";

		JSONObject json = new JSONObject();
		json.put(key, value);

		BDDMockito.when(mockMetricsCacheService.getViolationsByType(BDDMockito.any(),
				BDDMockito.anyString())).thenReturn(json);

		mockMvc.perform(MockMvcRequestBuilders
				.get("/metrics/violations-by-type?period=last-four-weeks&type=foo"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content().json(json.toJSONString()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_DASHBOARDS_NAME})
	public void testGetViolationsByPeriod() throws Exception {
		String key = "test";
		String value = "value";

		JSONObject json = new JSONObject();
		json.put(key, value);

		BDDMockito
				.when(mockMetricsCacheService.getViolationsByPeriod(BDDMockito.any(),
						BDDMockito.anyString()))
				.thenReturn(json);

		mockMvc.perform(
				MockMvcRequestBuilders
						.get("/metrics/violations-by-period?period=last-week&type=foo"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content().json(json.toJSONString()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_DASHBOARDS_NAME})
	public void testGetViolationsByPeriodAndType() throws Exception {
		String key = "test";
		String value = "value";

		JSONObject json = new JSONObject();
		json.put(key, value);

		BDDMockito
				.when(mockMetricsCacheService.getViolationsByPeriodAndType(BDDMockito.any(),
						BDDMockito.anyString()))
				.thenReturn(json);

		mockMvc.perform(
				MockMvcRequestBuilders
						.get("/metrics/violations-by-period-and-type?period=last-six-months&type=foo"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content().json(json.toJSONString()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_DASHBOARDS_NAME})
	public void testGetScansByPeriod() throws Exception {
		String key = "test";
		String value = "value";

		JSONObject json = new JSONObject();
		json.put(key, value);

		BDDMockito
				.when(mockMetricsCacheService.getScansByPeriod(BDDMockito.any(),
						BDDMockito.anyString()))
				.thenReturn(json);

		mockMvc.perform(MockMvcRequestBuilders
				.get("/metrics/scans-by-period?period=all-time&type=foo"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content().json(json.toJSONString()));
	}

}
