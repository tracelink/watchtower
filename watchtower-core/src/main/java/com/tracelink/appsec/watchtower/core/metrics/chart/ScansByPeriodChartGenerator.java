package com.tracelink.appsec.watchtower.core.metrics.chart;

import java.util.List;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanEntity;

import net.minidev.json.JSONObject;

/**
 * Implementation of an {@link AbstractChartGenerator} to create a graph of number of scans over
 * time. Counts scans for each bucket of given scans and reduces them to a single {@link Long}. The
 * resultant chart contains one set of data with all the scan counts.
 *
 * @author mcool
 */
public class ScansByPeriodChartGenerator extends
		AbstractChartGenerator<AbstractScanEntity<?, ?>, Long> {

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected Long accumulate(Long partialResult, List<AbstractScanEntity<?, ?>> items) {
		return partialResult + items.size();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected Long getIdentity() {
		return 0L;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected JSONObject getDatasets(List<Long> result) {
		JSONObject datasets = new JSONObject();
		datasets.put("counts", result);
		return datasets;
	}

}
