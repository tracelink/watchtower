package com.tracelink.appsec.watchtower.core.metrics.chart;

import java.util.Arrays;
import java.util.Collections;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;

import net.minidev.json.JSONObject;

public class ScansByPeriodChartGeneratorTest {

	@Test
	public void testAccumulate() {
		AbstractScanEntity<?, ?> scan = new PullRequestScanEntity();
		ScansByPeriodChartGenerator chartGenerator = new ScansByPeriodChartGenerator();
		Assertions.assertEquals(2, chartGenerator.accumulate(1L, Collections.singletonList(scan)),
				0.001);
	}

	@Test
	public void testIdentity() {
		Assertions.assertEquals(0, new ScansByPeriodChartGenerator().getIdentity(), 0.001);
	}

	@Test
	public void testGetDatasets() {
		ScansByPeriodChartGenerator chartGenerator = new ScansByPeriodChartGenerator();
		JSONObject results = chartGenerator.getDatasets(Arrays.asList(0L, 1L, 2L, 3L, 4L));
		Assertions.assertEquals("[0, 1, 2, 3, 4]", results.getAsString("counts"));
	}
}
