package com.tracelink.appsec.watchtower.core.metrics.chart;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.stream.Collectors;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanEntity;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanViolationEntity;

import net.minidev.json.JSONObject;

/**
 * Implementation of an {@link AbstractChartGenerator} to create a graph of number of violations
 * found of each type over time. Groups violations for each bucket of given scans by name and
 * reduces them to a map from violation name to number of violations. The resultant chart contains
 * multiple sets of data that map violation names to lists of violation counts, which correspond to
 * the number of violations of each type in a given bucket of time.
 *
 * @author mcool
 */
public class ViolationsByPeriodAndTypeChartGenerator extends
		AbstractChartGenerator<AbstractScanEntity<?, ?>, Map<String, Long>> {

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected Map<String, Long> accumulate(Map<String, Long> partialResult,
			List<AbstractScanEntity<?, ?>> items) {
		items.stream().map(AbstractScanEntity::getViolations)
				.flatMap(List::stream)
				.filter(v -> !v.getSeverity().equals(RulePriority.INFORMATIONAL))
				.map(AbstractScanViolationEntity::getViolationName)
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
		Map<String, List<Long>> countsMap = result.stream().map(Map::keySet)
				.flatMap(Set::stream).distinct().collect(Collectors
						.toMap(Function.identity(), name -> result.stream()
								.map(map -> map.getOrDefault(name, 0L))
								.collect(Collectors.toList())));
		JSONObject datasets = new JSONObject();
		countsMap.forEach(datasets::put);
		return datasets;
	}

}
