package com.tracelink.appsec.watchtower.core.rest.metrics;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.metrics.MetricsCacheService;
import com.tracelink.appsec.watchtower.core.metrics.bucketer.BucketerTimePeriod;
import com.tracelink.appsec.watchtower.core.scan.ScanType;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanType;

import net.minidev.json.JSONObject;

/**
 * Controller for a REST-based API that gathers metrics on past scans, pull requests, repositories
 * and violations.
 *
 * @author mcool
 */
@RestController
@RequestMapping("/rest/metrics")
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_DASHBOARDS_NAME + "')")
public class MetricsRestController {

	private MetricsCacheService metricsCacheService;
	private List<ScanType> scanTypes = new ArrayList<>();


	public MetricsRestController(@Autowired MetricsCacheService metricsCacheService) {
		this.metricsCacheService = metricsCacheService;
		this.scanTypes.addAll(Arrays.asList(CodeScanType.values()));
		this.scanTypes.addAll(Arrays.asList(ImageScanType.values()));
	}

	@GetMapping("/periods")
	ResponseEntity<List<String>> getPeriods() {
		return ResponseEntity
				.ok(Arrays.stream(BucketerTimePeriod.values()).map(BucketerTimePeriod::getPeriod)
						.collect(Collectors.toList()));
	}

	@GetMapping("/scantypes")
	ResponseEntity<List<String>> getScanTypes() {
		return ResponseEntity.ok(this.scanTypes.stream().map(ScanType::getTypeName)
				.collect(Collectors.toList()));
	}

	/**
	 * Gets metrics about the number of violations of each type found within a certain length of
	 * time.
	 *
	 * @param period a string representing a certain length of time over which to gather metrics
	 * @return map containing labels for each violation type and a dataset for number of violations
	 *         of each type
	 */
	@GetMapping("/violations-by-type")
	ResponseEntity<JSONObject> getViolationsByType(@RequestParam String type,
			@RequestParam String period) {
		return ResponseEntity
				.ok(metricsCacheService.getViolationsByType(getScanType(type), period));
	}


	/**
	 * Gets metrics about the number of violations of found within a certain length of time. Data is
	 * divided into time periods of appropriate length.
	 *
	 * @param period a string representing a certain length of time over which to gather metrics
	 * @return map containing labels for each subdivided time period and a dataset for number of
	 *         violations found during each period
	 */
	@GetMapping("/violations-by-period")
	ResponseEntity<JSONObject> getViolationsByPeriod(@RequestParam String type,
			@RequestParam String period) {
		return ResponseEntity
				.ok(metricsCacheService.getViolationsByPeriod(getScanType(type), period));
	}

	/**
	 * Gets metrics about the number of violations of each type found within a certain length of
	 * time. Data is divided into time periods of appropriate length.
	 *
	 * @param period a string representing a certain length of time over which to gather metrics
	 * @return map containing labels for each subdivided time period and datasets for number of
	 *         violations found during each period for each violation type
	 */
	@GetMapping("/violations-by-period-and-type")
	ResponseEntity<JSONObject> getViolationsByPeriodAndType(@RequestParam String type,
			@RequestParam String period) {
		return ResponseEntity.ok(
				metricsCacheService.getViolationsByPeriodAndType(getScanType(type),
						period));
	}

	/**
	 * Gets metrics about the number of scans completed within a certain length of time. Data is
	 * divided into time periods of appropriate length.
	 *
	 * @param period a string representing a certain length of time over which to gather metrics
	 * @return map containing labels for each subdivided time period and a dataset for number of
	 *         scans completed during each period
	 */
	@GetMapping("/scans-by-period")
	ResponseEntity<JSONObject> getScansByPeriod(@RequestParam String type,
			@RequestParam String period) {
		return ResponseEntity
				.ok(metricsCacheService.getScansByPeriod(getScanType(type), period));
	}

	@GetMapping(value = {"/scans-completed", "/scans-completed/{scanType}"})
	public ResponseEntity<JSONObject> getScansCompleted(@PathVariable Optional<String> scanType) {
		List<ScanType> types =
				scanType.isPresent() ? Arrays.asList(getScanType(scanType.get()))
						: this.scanTypes;

		return ResponseEntity
				.ok(getTopLevelMetric((metricsCacheService::getScanCount), types));
	}

	@GetMapping(value = {"/violations-found", "/violations-found/{scanType}"})
	public ResponseEntity<JSONObject> getViolationsFound(@PathVariable Optional<String> scanType) {
		List<ScanType> types =
				scanType.isPresent() ? Arrays.asList(getScanType(scanType.get()))
						: this.scanTypes;

		return ResponseEntity
				.ok(getTopLevelMetric((metricsCacheService::getViolationCount), types));
	}

	@GetMapping(value = {"/average-scan-time", "/average-scan-time/{scanType}"})
	public ResponseEntity<JSONObject> getAverageScanTime(@PathVariable Optional<String> scanType) {
		List<ScanType> types =
				scanType.isPresent() ? Arrays.asList(getScanType(scanType.get()))
						: this.scanTypes;

		return ResponseEntity
				.ok(getTopLevelMetric((metricsCacheService::getAverageScanTimeString), types));
	}

	private JSONObject getTopLevelMetric(Function<ScanType, Object> metricsCall,
			List<ScanType> scanTypes) {
		JSONObject scanComplete = new JSONObject();
		for (ScanType type : scanTypes) {
			scanComplete.put(type.getDisplayName(), String.valueOf(metricsCall.apply(type)));
		}
		return scanComplete;
	}

	private ScanType getScanType(String type) {
		for (ScanType t : this.scanTypes) {
			if (t.getTypeName().equalsIgnoreCase(type)) {
				return t;
			}
		}
		throw new IllegalArgumentException("Unknown Type");
	}

}
