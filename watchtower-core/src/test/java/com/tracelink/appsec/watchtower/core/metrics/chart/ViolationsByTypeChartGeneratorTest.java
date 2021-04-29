package com.tracelink.appsec.watchtower.core.metrics.chart;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.BDDMockito;

import com.tracelink.appsec.watchtower.core.scan.upload.entity.UploadScanEntity;
import com.tracelink.appsec.watchtower.core.scan.upload.entity.UploadViolationEntity;

import net.minidev.json.JSONObject;

public class ViolationsByTypeChartGeneratorTest {

	@Test
	public void testAccumulate() {
		UploadScanEntity scan = BDDMockito.mock(UploadScanEntity.class);
		UploadViolationEntity xxe = new UploadViolationEntity();
		xxe.setViolationName("XXE");
		UploadViolationEntity ser = new UploadViolationEntity();
		ser.setViolationName("SER");
		BDDMockito.when(scan.getViolations()).thenReturn(Arrays.asList(xxe, ser));
		Map<String, Long> map = new TreeMap<>();
		map.put("XXE", 1L);
		ViolationsByTypeChartGenerator chartGenerator = new ViolationsByTypeChartGenerator();
		Map<String, Long> partialResult = chartGenerator
				.accumulate(map, Collections.singletonList(scan));
		Assertions.assertEquals(2, partialResult.size());
		Assertions.assertEquals(2L, partialResult.get("XXE"), 0.001);
		Assertions.assertEquals(1L, partialResult.get("SER"), 0.001);
	}

	@Test
	public void testIdentity() {
		Map<String, Long> identity = new ViolationsByTypeChartGenerator().getIdentity();
		Assertions.assertTrue(identity.isEmpty());
		Assertions.assertTrue(identity instanceof TreeMap);
	}

	@Test
	public void testGetDatasets() {
		Map<String, Long> map1 = new TreeMap<>();
		map1.put("XXE", 2L);
		map1.put("SER", 1L);
		Map<String, Long> map2 = new TreeMap<>();
		map2.put("XXE", 1L);
		ViolationsByTypeChartGenerator chartGenerator = new ViolationsByTypeChartGenerator();
		JSONObject results = chartGenerator.getDatasets(Arrays.asList(map1, new TreeMap<>(), map2));
		Assertions.assertEquals("[SER, XXE]", results.getAsString("labels"));
		Assertions.assertEquals("[1, 3]", results.getAsString("counts"));
	}

}
