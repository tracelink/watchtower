package com.tracelink.appsec.watchtower.core.metrics;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.scan.ScanType;

import net.minidev.json.JSONObject;

/**
 * Controller for a REST-based API that gathers metrics on past scans, pull requests, repositories
 * and violations.
 * <p>
 * Does not use the basic-auth scheme for authentication. Uses cookies
 *
 * @author mcool
 */
@RestController
@RequestMapping("/metrics")
@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_DASHBOARDS_NAME + "')")
public class MetricsRestController {

	private MetricsCacheService metricsCacheService;

	public MetricsRestController(@Autowired MetricsCacheService metricsCacheService) {
		this.metricsCacheService = metricsCacheService;
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
				.ok(metricsCacheService.getViolationsByType(ScanType.ofType(type), period));
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
				.ok(metricsCacheService.getViolationsByPeriod(ScanType.ofType(type), period));
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
				metricsCacheService.getViolationsByPeriodAndType(ScanType.ofType(type), period));
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
				.ok(metricsCacheService.getScansByPeriod(ScanType.ofType(type), period));
	}

}
