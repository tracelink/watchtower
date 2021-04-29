package com.tracelink.appsec.watchtower.core.metrics.chart;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import com.tracelink.appsec.watchtower.core.logging.CoreLogWatchExtension;

import net.minidev.json.JSONObject;

public class AbstractChartGeneratorTest {

	@RegisterExtension
	public CoreLogWatchExtension loggerRule = CoreLogWatchExtension.forClass(AbstractChartGenerator.class);

	@Test
	public void testReduceAndGetResults() {
		MockChartGenerator chartGenerator = new MockChartGenerator();
		chartGenerator.reduce(Arrays.asList(Arrays.asList(1L, 2L), Arrays.asList(3L, 4L, 5L)));
		JSONObject results = chartGenerator.getResults(Arrays.asList("foo", "bar"));
		Assertions.assertEquals("[foo, bar]", results.getAsString("labels"));
		Assertions.assertEquals("[5, 14]", results.getAsString("sums"));

		chartGenerator.reduce(Arrays.asList(Arrays.asList(0L), Arrays.asList(6L)));
		results = chartGenerator.getResults(Arrays.asList("foo2", "bar2"));
		Assertions.assertEquals("[foo2, bar2]", results.getAsString("labels"));
		Assertions.assertEquals("[5, 20]", results.getAsString("sums"));
	}

	@Test
	public void testReduceBucketMismatch() {
		MockChartGenerator chartGenerator = new MockChartGenerator();
		chartGenerator.reduce(Arrays.asList(Arrays.asList(1L, 2L), Arrays.asList(3L, 4L, 5L)));

		chartGenerator.reduce(Arrays.asList(Arrays.asList(0L)));
		JSONObject results = chartGenerator.getResults(Arrays.asList("foo", "bar"));
		Assertions.assertEquals("[foo, bar]", results.getAsString("labels"));
		Assertions.assertEquals("[5, 14]", results.getAsString("sums"));

		Assertions.assertEquals(1, loggerRule.getMessages().size());
		Assertions.assertEquals(
				"Number of buckets for partial results and bucketed items do not match",
				loggerRule.getMessages().get(0));
	}

	private static class MockChartGenerator extends AbstractChartGenerator<Long, Long> {

		@Override
		protected Long accumulate(Long partialResult, List<Long> items) {
			return partialResult + items.stream().reduce(0L, Long::sum);
		}

		@Override
		protected Long getIdentity() {
			return 2L;
		}

		@Override
		protected JSONObject getDatasets(List<Long> result) {
			JSONObject datasets = new JSONObject();
			datasets.put("sums", result);
			return datasets;
		}
	}

}
