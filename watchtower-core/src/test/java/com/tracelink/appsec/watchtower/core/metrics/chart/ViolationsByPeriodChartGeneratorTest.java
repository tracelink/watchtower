package com.tracelink.appsec.watchtower.core.metrics.chart;

import java.util.Arrays;
import java.util.Collections;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.BDDMockito;

import com.tracelink.appsec.watchtower.core.scan.upload.entity.UploadScanEntity;

import net.minidev.json.JSONObject;

public class ViolationsByPeriodChartGeneratorTest {

	@Test
	public void testAccumulate() {
		UploadScanEntity scan = BDDMockito.mock(UploadScanEntity.class);
		BDDMockito.when(scan.getNumViolations()).thenReturn(3L);
		ViolationsByPeriodChartGenerator chartGenerator = new ViolationsByPeriodChartGenerator();
		Assertions.assertEquals(4L, chartGenerator.accumulate(1L, Collections.singletonList(scan)),
				0.001);
	}

	@Test
	public void testIdentity() {
		Assertions.assertEquals(0L, new ViolationsByPeriodChartGenerator().getIdentity(), 0.001);
	}

	@Test
	public void testGetDatasets() {
		ViolationsByPeriodChartGenerator chartGenerator = new ViolationsByPeriodChartGenerator();
		JSONObject results = chartGenerator.getDatasets(Arrays.asList(0L, 1L, 2L, 3L, 4L));
		Assertions.assertEquals("[0, 1, 2, 3, 4]", results.getAsString("counts"));
	}

}
