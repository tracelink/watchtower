package com.tracelink.appsec.watchtower.core.metrics.chart;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.stream.Collectors;

import com.tracelink.appsec.watchtower.core.scan.code.AbstractScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.AbstractViolationEntity;

import net.minidev.json.JSONObject;

/**
 * Implementation of an {@link AbstractChartGenerator} to create a graph of number of violations
 * found of each type. Groups violations for each bucket of given scans by name and reduces them to
 * a map from violation name to number of violations. The resultant chart contains one set of data
 * with all the violation counts, and provides the violation names as labels. It ignores the time
 * bucketing of the scans provided.
 *
 * @author mcool
 */
public class ViolationsByTypeChartGenerator extends
		AbstractChartGenerator<AbstractScanEntity<?, ?>, Map<String, Long>> {

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected Map<String, Long> accumulate(Map<String, Long> partialResult,
			List<AbstractScanEntity<?, ?>> items) {
		items.stream().map(AbstractScanEntity::getViolations)
				.flatMap(List::stream).map(AbstractViolationEntity::getViolationName)
				.collect(Collectors.groupingBy(Function.identity(), Collectors.counting()))
				.forEach((k, v) -> partialResult.merge(k, v, Long::sum));
		return partialResult;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected Map<String, Long> getIdentity() {
		return new TreeMap<>();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected JSONObject getDatasets(List<Map<String, Long>> result) {
		List<String> labels = new ArrayList<>();
		List<Long> counts = new ArrayList<>();
		result.stream().map(Map::keySet).flatMap(Set::stream).distinct().sorted()
				.forEach(name -> {
					labels.add(name);
					counts.add(result.stream().mapToLong(map -> map.getOrDefault(name, 0L)).sum());
				});
		JSONObject datasets = new JSONObject();
		datasets.put("labels", labels);
		datasets.put("counts", counts);
		return datasets;
	}

}
