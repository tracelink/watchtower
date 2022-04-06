package com.tracelink.appsec.watchtower.core.rest.metrics;

import java.util.Arrays;
import java.util.stream.Collectors;

import org.json.JSONArray;
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
import com.tracelink.appsec.watchtower.core.metrics.MetricsCacheService;
import com.tracelink.appsec.watchtower.core.metrics.bucketer.BucketerTimePeriod;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;

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
				.get("/rest/metrics/violations-by-type?period=last-four-weeks&type=foo"))
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
						.get("/rest/metrics/violations-by-period?period=last-week&type=foo"))
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
						.get("/rest/metrics/violations-by-period-and-type?period=last-six-months&type=foo"))
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
				.get("/rest/metrics/scans-by-period?period=all-time&type=foo"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content().json(json.toJSONString()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_DASHBOARDS_NAME})
	public void testGetPeriods() throws Exception {
		String jsonContent = new JSONArray(Arrays.stream(BucketerTimePeriod.values())
				.map(BucketerTimePeriod::getPeriod).collect(Collectors.toList())).toString();
		mockMvc.perform(MockMvcRequestBuilders
				.get("/rest/metrics/periods"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content().json(jsonContent));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_DASHBOARDS_NAME})
	public void testGetScanTypes() throws Exception {
		String jsonContent =
				new JSONArray(Arrays.stream(CodeScanType.values()).map(CodeScanType::getTypeName)
						.collect(Collectors.toList())).toString();
		mockMvc.perform(MockMvcRequestBuilders
				.get("/rest/metrics/scantypes"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content().json(jsonContent));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_DASHBOARDS_NAME})
	public void testGetScansCompleted() throws Exception {
		long upload = 20;
		long pr = 10;
		BDDMockito.when(mockMetricsCacheService.getScanCount(CodeScanType.UPLOAD)).thenReturn(upload);
		BDDMockito.when(mockMetricsCacheService.getScanCount(CodeScanType.PULL_REQUEST)).thenReturn(pr);

		JSONObject jsonContent = new JSONObject();
		jsonContent.put(CodeScanType.UPLOAD.getDisplayName(), String.valueOf(upload));
		jsonContent.put(CodeScanType.PULL_REQUEST.getDisplayName(), String.valueOf(pr));

		mockMvc.perform(MockMvcRequestBuilders
				.get("/rest/metrics/scans-completed"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content().json(jsonContent.toString()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_DASHBOARDS_NAME})
	public void testGetScansCompletedSpecific() throws Exception {
		long upload = 20;
		BDDMockito.when(mockMetricsCacheService.getScanCount(CodeScanType.UPLOAD)).thenReturn(upload);

		JSONObject jsonContent = new JSONObject();
		jsonContent.put(CodeScanType.UPLOAD.getDisplayName(), String.valueOf(upload));

		mockMvc.perform(MockMvcRequestBuilders
				.get("/rest/metrics/scans-completed/" + CodeScanType.UPLOAD.getTypeName()))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content().json(jsonContent.toString()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_DASHBOARDS_NAME})
	public void testGetViolationsFound() throws Exception {
		long upload = 20;
		long pr = 10;
		BDDMockito.when(mockMetricsCacheService.getViolationCount(CodeScanType.UPLOAD))
				.thenReturn(upload);
		BDDMockito.when(mockMetricsCacheService.getViolationCount(CodeScanType.PULL_REQUEST))
				.thenReturn(pr);

		JSONObject jsonContent = new JSONObject();
		jsonContent.put(CodeScanType.UPLOAD.getDisplayName(), String.valueOf(upload));
		jsonContent.put(CodeScanType.PULL_REQUEST.getDisplayName(), String.valueOf(pr));

		mockMvc.perform(MockMvcRequestBuilders
				.get("/rest/metrics/violations-found"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content().json(jsonContent.toString()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_DASHBOARDS_NAME})
	public void testGetViolationsFoundSpecific() throws Exception {
		long upload = 20;
		BDDMockito.when(mockMetricsCacheService.getViolationCount(CodeScanType.UPLOAD))
				.thenReturn(upload);

		JSONObject jsonContent = new JSONObject();
		jsonContent.put(CodeScanType.UPLOAD.getDisplayName(), String.valueOf(upload));

		mockMvc.perform(MockMvcRequestBuilders
				.get("/rest/metrics/violations-found/" + CodeScanType.UPLOAD.getTypeName()))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content().json(jsonContent.toString()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_DASHBOARDS_NAME})
	public void testGetAverageScanTime() throws Exception {
		String upload = "2";
		String pr = "1";
		BDDMockito.when(mockMetricsCacheService.getAverageScanTimeString(CodeScanType.UPLOAD))
				.thenReturn(upload);
		BDDMockito.when(mockMetricsCacheService.getAverageScanTimeString(CodeScanType.PULL_REQUEST))
				.thenReturn(pr);

		JSONObject jsonContent = new JSONObject();
		jsonContent.put(CodeScanType.UPLOAD.getDisplayName(), String.valueOf(upload));
		jsonContent.put(CodeScanType.PULL_REQUEST.getDisplayName(), String.valueOf(pr));

		mockMvc.perform(MockMvcRequestBuilders
				.get("/rest/metrics/average-scan-time"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content().json(jsonContent.toString()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_DASHBOARDS_NAME})
	public void testGetAverageScanTimeSpecific() throws Exception {
		String upload = "2";
		BDDMockito.when(mockMetricsCacheService.getAverageScanTimeString(CodeScanType.UPLOAD))
				.thenReturn(upload);

		JSONObject jsonContent = new JSONObject();
		jsonContent.put(CodeScanType.UPLOAD.getDisplayName(), String.valueOf(upload));

		mockMvc.perform(MockMvcRequestBuilders
				.get("/rest/metrics/average-scan-time/" + CodeScanType.UPLOAD.getTypeName()))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content().json(jsonContent.toString()));
	}

}
