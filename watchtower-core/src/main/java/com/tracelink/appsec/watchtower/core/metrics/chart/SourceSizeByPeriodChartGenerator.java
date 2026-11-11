package com.tracelink.appsec.watchtower.core.metrics.chart;

import java.util.List;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;

import net.minidev.json.JSONObject;

/**
 * Implementation of an {@link AbstractChartGenerator} to create a graph of the average byte size
 * of source scanned over time (IMPROVEMENT_PLAN.md item 6.5). Only meaningful for PR scans -
 * upload and image scans have no BB repo context - so this is registered for
 * {@code CodeScanType.PULL_REQUEST} only; any non-{@link PullRequestScanEntity} item is ignored
 * rather than causing a cast failure, in case that ever changes.
 * <p>
 * Accumulates a running sum and count (not a running average) across pages, since averaging
 * partial averages without their counts would weight each page equally regardless of size.
 *
 * @author mcool
 */
public class SourceSizeByPeriodChartGenerator extends
		AbstractChartGenerator<AbstractScanEntity<?, ?>, SourceSizeByPeriodChartGenerator.SizeAccumulator> {

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected SizeAccumulator accumulate(SizeAccumulator partialResult,
			List<AbstractScanEntity<?, ?>> items) {
		long sum = partialResult.sum();
		long count = partialResult.count();
		for (AbstractScanEntity<?, ?> item : items) {
			if (item instanceof PullRequestScanEntity pr && pr.getSourceSizeBytes() > 0) {
				sum += pr.getSourceSizeBytes();
				count++;
			}
		}
		return new SizeAccumulator(sum, count);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected SizeAccumulator getIdentity() {
		return new SizeAccumulator(0L, 0L);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected JSONObject getDatasets(List<SizeAccumulator> result) {
		JSONObject datasets = new JSONObject();
		datasets.put("averageSourceSizeBytes",
				result.stream().map(SizeAccumulator::average).toList());
		return datasets;
	}

	record SizeAccumulator(long sum, long count) {
		double average() {
			return count == 0 ? 0.0 : (double) sum / count;
		}
	}

}
