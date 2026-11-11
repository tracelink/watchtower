package com.tracelink.appsec.watchtower.core.metrics.chart;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.metrics.chart.SourceSizeByPeriodChartGenerator.SizeAccumulator;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanEntity;

import net.minidev.json.JSONObject;

public class SourceSizeByPeriodChartGeneratorTest {

	@Test
	public void testAccumulateSumsAndCountsOnlyPositiveSizes() {
		PullRequestScanEntity withSize = new PullRequestScanEntity();
		withSize.setSourceSizeBytes(100);
		PullRequestScanEntity zeroSize = new PullRequestScanEntity();
		zeroSize.setSourceSizeBytes(0);

		SourceSizeByPeriodChartGenerator chartGenerator = new SourceSizeByPeriodChartGenerator();
		SizeAccumulator result = chartGenerator.accumulate(new SizeAccumulator(0L, 0L),
				Arrays.asList(withSize, zeroSize));

		Assertions.assertEquals(100L, result.sum());
		Assertions.assertEquals(1L, result.count());
	}

	@Test
	public void testAccumulateIgnoresNonPullRequestScans() {
		AbstractScanEntity<?, ?> uploadScan = new UploadScanEntity();
		SourceSizeByPeriodChartGenerator chartGenerator = new SourceSizeByPeriodChartGenerator();
		SizeAccumulator result = chartGenerator.accumulate(new SizeAccumulator(0L, 0L),
				Collections.singletonList(uploadScan));

		Assertions.assertEquals(0L, result.sum());
		Assertions.assertEquals(0L, result.count());
	}

	@Test
	public void testIdentity() {
		SizeAccumulator identity = new SourceSizeByPeriodChartGenerator().getIdentity();
		Assertions.assertEquals(0L, identity.sum());
		Assertions.assertEquals(0L, identity.count());
	}

	@Test
	public void testGetDatasetsComputesAverages() {
		SourceSizeByPeriodChartGenerator chartGenerator = new SourceSizeByPeriodChartGenerator();
		List<SizeAccumulator> result = Arrays.asList(
				new SizeAccumulator(0L, 0L),
				new SizeAccumulator(300L, 3L));
		JSONObject datasets = chartGenerator.getDatasets(result);
		Assertions.assertEquals("[0.0, 100.0]",
				datasets.getAsString("averageSourceSizeBytes"));
	}
}
