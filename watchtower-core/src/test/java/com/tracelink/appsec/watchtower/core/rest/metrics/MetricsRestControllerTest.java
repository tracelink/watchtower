package com.tracelink.appsec.watchtower.core.rest.metrics;

import java.time.LocalDate;
import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.json.JSONArray;
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
import com.tracelink.appsec.watchtower.core.metrics.MetricsCacheService;
import com.tracelink.appsec.watchtower.core.metrics.bucketer.BucketerTimePeriod;
import com.tracelink.appsec.watchtower.core.scan.ScanType;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanType;

import net.minidev.json.JSONObject;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class MetricsRestControllerTest {
	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
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
				.get("/rest/metrics/violations-by-type?period=last-four-weeks&type="
						+ CodeScanType.PULL_REQUEST.getTypeName()))
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
						.get("/rest/metrics/violations-by-period?period=last-week&type="
								+ CodeScanType.PULL_REQUEST.getTypeName()))
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
						.get("/rest/metrics/violations-by-period-and-type?period=last-six-months&type="
								+ CodeScanType.PULL_REQUEST.getTypeName()))
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
				.get("/rest/metrics/scans-by-period?period=all-time&type="
						+ CodeScanType.PULL_REQUEST.getTypeName()))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content().json(json.toJSONString()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_DASHBOARDS_NAME,
			CorePrivilege.SCAN_ADMIN_NAME})
	public void testGetPrPerformanceByPeriod() throws Exception {
		JSONObject json = new JSONObject();
		json.put("labels", Arrays.asList("Today"));
		json.put("totalMs", Arrays.asList(1200D));
		BDDMockito.when(mockMetricsCacheService.getPrPerformanceByPeriod("last-thirty-days"))
				.thenReturn(json);

		mockMvc.perform(MockMvcRequestBuilders.get("/rest/metrics/pr-performance-by-period")
				.param("period", "last-thirty-days"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().json(json.toJSONString()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_DASHBOARDS_NAME,
			CorePrivilege.SCAN_ADMIN_NAME})
	public void repositoryDurationAcceptsPresetAndCustomRanges() throws Exception {
		JSONObject json = new JSONObject();
		json.put("labels", Arrays.asList("Today"));
		json.put("samples", Arrays.asList(2));
		json.put("totalMs", Arrays.asList(4000D));
		BDDMockito.when(mockMetricsCacheService.getScanDurationByPeriod(
				CodeScanType.REPOSITORY, "all-time")).thenReturn(json);
		mockMvc.perform(MockMvcRequestBuilders.get("/rest/metrics/scan-duration-by-period")
				.param("type", "repository").param("period", "all-time"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().json(json.toJSONString()));

		LocalDate today = LocalDate.now();
		BDDMockito.when(mockMetricsCacheService.getScanDurationByPeriod(
				CodeScanType.REPOSITORY, today, today)).thenReturn(json);
		mockMvc.perform(MockMvcRequestBuilders.get("/rest/metrics/scan-duration-by-period")
				.param("type", "repository").param("period", "custom")
				.param("start", today.toString()).param("end", today.toString()))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().json(json.toJSONString()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_DASHBOARDS_NAME})
	public void customScanRangeUsesInclusiveDatesInsteadOfPreset() throws Exception {
		LocalDate start = LocalDate.of(2026, 9, 1);
		LocalDate end = LocalDate.of(2026, 9, 23);
		JSONObject json = new JSONObject();
		json.put("labels", Arrays.asList("2026-09-01 – 2026-09-23"));
		json.put("counts", Arrays.asList(42));
		BDDMockito.when(mockMetricsCacheService.getScansByPeriod(
				CodeScanType.PULL_REQUEST, start, end)).thenReturn(json);

		mockMvc.perform(MockMvcRequestBuilders.get("/rest/metrics/scans-by-period")
				.param("type", CodeScanType.PULL_REQUEST.getTypeName())
				.param("period", "last-week")
				.param("start", start.toString())
				.param("end", end.toString()))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().json(json.toJSONString()));

		BDDMockito.verify(mockMetricsCacheService).getScansByPeriod(
				CodeScanType.PULL_REQUEST, start, end);
		BDDMockito.verify(mockMetricsCacheService, BDDMockito.never())
				.getScansByPeriod(BDDMockito.any(), BDDMockito.anyString());
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
		Stream<ScanType> sts = Stream
				.concat(Arrays.stream(CodeScanType.values()),
						Arrays.stream(ImageScanType.values()));
		String jsonContent =
				new JSONArray(sts.map(ScanType::getTypeName).collect(Collectors.toList()))
						.toString();
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
		BDDMockito.when(mockMetricsCacheService.getScanCount(CodeScanType.UPLOAD))
				.thenReturn(upload);
		BDDMockito.when(mockMetricsCacheService.getScanCount(CodeScanType.PULL_REQUEST))
				.thenReturn(pr);

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
		BDDMockito.when(mockMetricsCacheService.getScanCount(CodeScanType.UPLOAD))
				.thenReturn(upload);

		JSONObject jsonContent = new JSONObject();
		jsonContent.put(CodeScanType.UPLOAD.getDisplayName(), String.valueOf(upload));

		mockMvc.perform(MockMvcRequestBuilders
				.get("/rest/metrics/scans-completed/" + CodeScanType.UPLOAD.getTypeName()))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content().json(jsonContent.toString()));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.SCAN_DASHBOARDS_NAME})
	public void testGetScansToday() throws Exception {
		long upload = 4;
		long pr = 2;
		BDDMockito.when(mockMetricsCacheService.getScanCountToday(CodeScanType.UPLOAD))
				.thenReturn(upload);
		BDDMockito.when(mockMetricsCacheService.getScanCountToday(CodeScanType.PULL_REQUEST))
				.thenReturn(pr);

		JSONObject jsonContent = new JSONObject();
		jsonContent.put(CodeScanType.UPLOAD.getDisplayName(), String.valueOf(upload));
		jsonContent.put(CodeScanType.PULL_REQUEST.getDisplayName(), String.valueOf(pr));

		mockMvc.perform(MockMvcRequestBuilders
				.get("/rest/metrics/scans-today"))
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
