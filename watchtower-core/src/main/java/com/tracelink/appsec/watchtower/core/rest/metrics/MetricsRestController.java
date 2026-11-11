package com.tracelink.appsec.watchtower.core.rest.metrics;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.BiFunction;
import java.util.function.Supplier;
import java.time.LocalDate;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.metrics.MetricsCacheService;
import com.tracelink.appsec.watchtower.core.metrics.bucketer.BucketerTimePeriod;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
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

	private static final Logger LOG = LoggerFactory.getLogger(MetricsRestController.class);

	private MetricsCacheService metricsCacheService;
	private final RuleService ruleService;
	private List<ScanType> scanTypes = new ArrayList<>();


	public MetricsRestController(@Autowired MetricsCacheService metricsCacheService,
			@Autowired RuleService ruleService) {
		this.metricsCacheService = metricsCacheService;
		this.ruleService = ruleService;
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
			@RequestParam(defaultValue = "last-four-weeks") String period,
			@RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate start,
			@RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate end) {
		LOG.debug("GET /rest/metrics/violations-by-type type=" + type + " period=" + period);
		ScanType scanType = getScanType(type);
		return ResponseEntity.ok(RuleScannerLabels.label(range(start, end,
				() -> metricsCacheService.getViolationsByType(scanType, period),
				(from, to) -> metricsCacheService.getViolationsByType(scanType, from, to)), ruleService));
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
			@RequestParam(defaultValue = "last-four-weeks") String period,
			@RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate start,
			@RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate end) {
		LOG.debug("GET /rest/metrics/violations-by-period type=" + type + " period=" + period);
		ScanType scanType = getScanType(type);
		return ResponseEntity.ok(range(start, end,
				() -> metricsCacheService.getViolationsByPeriod(scanType, period),
				(from, to) -> metricsCacheService.getViolationsByPeriod(scanType, from, to)));
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
			@RequestParam(defaultValue = "last-four-weeks") String period,
			@RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate start,
			@RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate end) {
		LOG.debug("GET /rest/metrics/violations-by-period-and-type type=" + type + " period="
				+ period);
		ScanType scanType = getScanType(type);
		return ResponseEntity.ok(range(start, end,
				() -> metricsCacheService.getViolationsByPeriodAndType(scanType, period),
				(from, to) -> metricsCacheService.getViolationsByPeriodAndType(scanType, from, to)));
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
			@RequestParam(defaultValue = "last-four-weeks") String period,
			@RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate start,
			@RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate end) {
		LOG.debug("GET /rest/metrics/scans-by-period type=" + type + " period=" + period);
		ScanType scanType = getScanType(type);
		return ResponseEntity.ok(range(start, end,
				() -> metricsCacheService.getScansByPeriod(scanType, period),
				(from, to) -> metricsCacheService.getScansByPeriod(scanType, from, to)));
	}

	@GetMapping("/pr-performance-by-period")
	@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_ADMIN_NAME + "')")
	ResponseEntity<JSONObject> getPrPerformanceByPeriod(
			@RequestParam(defaultValue = "last-four-weeks") String period,
			@RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate start,
			@RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate end) {
		LOG.debug("GET /rest/metrics/pr-performance-by-period period=" + period);
		return ResponseEntity.ok(range(start, end,
				() -> metricsCacheService.getPrPerformanceByPeriod(period),
				metricsCacheService::getPrPerformanceByPeriod));
	}

	@GetMapping("/scan-duration-by-period")
	@PreAuthorize("hasAuthority('" + CorePrivilege.SCAN_ADMIN_NAME + "')")
	ResponseEntity<JSONObject> getScanDurationByPeriod(@RequestParam String type,
			@RequestParam(defaultValue = "all-time") String period,
			@RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate start,
			@RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate end) {
		ScanType scanType = getScanType(type);
		return ResponseEntity.ok(range(start, end,
				() -> metricsCacheService.getScanDurationByPeriod(scanType, period),
				(from, to) -> metricsCacheService.getScanDurationByPeriod(scanType, from, to)));
	}

	/**
	 * Gets metrics about the average byte size of source scanned within a certain length of
	 * time. PR scans only (IMPROVEMENT_PLAN.md item 6.5).
	 *
	 * @param period a string representing a certain length of time over which to gather metrics
	 * @return map containing labels for each subdivided time period and a dataset for average
	 *         source size during each period
	 */
	@GetMapping("/source-size-by-period")
	ResponseEntity<JSONObject> getSourceSizeByPeriod(@RequestParam String type,
			@RequestParam(defaultValue = "last-four-weeks") String period,
			@RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate start,
			@RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate end) {
		LOG.debug("GET /rest/metrics/source-size-by-period type=" + type + " period=" + period);
		ScanType scanType = getScanType(type);
		return ResponseEntity.ok(range(start, end,
				() -> metricsCacheService.getSourceSizeByPeriod(scanType, period),
				(from, to) -> metricsCacheService.getSourceSizeByPeriod(scanType, from, to)));
	}

	@GetMapping(value = {"/average-source-size", "/average-source-size/{scanType}"})
	public ResponseEntity<JSONObject> getAverageSourceSize(
			@PathVariable Optional<String> scanType) {
		LOG.debug("GET /rest/metrics/average-source-size scanType=" + scanType);
		List<ScanType> types =
				scanType.isPresent() ? Arrays.asList(getScanType(scanType.get()))
						: this.scanTypes;

		return ResponseEntity
				.ok(getTopLevelMetric((metricsCacheService::getAverageSourceSizeString), types));
	}

	@GetMapping(value = {"/scans-completed", "/scans-completed/{scanType}"})
	public ResponseEntity<JSONObject> getScansCompleted(@PathVariable Optional<String> scanType) {
		LOG.debug("GET /rest/metrics/scans-completed scanType=" + scanType);
		List<ScanType> types =
				scanType.isPresent() ? Arrays.asList(getScanType(scanType.get()))
						: this.scanTypes;

		return ResponseEntity
				.ok(getTopLevelMetric((metricsCacheService::getScanCount), types));
	}

	@GetMapping(value = {"/scans-today", "/scans-today/{scanType}"})
	public ResponseEntity<JSONObject> getScansToday(@PathVariable Optional<String> scanType) {
		LOG.debug("GET /rest/metrics/scans-today scanType=" + scanType);
		List<ScanType> types =
				scanType.isPresent() ? Arrays.asList(getScanType(scanType.get()))
						: this.scanTypes;

		return ResponseEntity
				.ok(getTopLevelMetric((metricsCacheService::getScanCountToday), types));
	}

	@GetMapping(value = {"/violations-found", "/violations-found/{scanType}"})
	public ResponseEntity<JSONObject> getViolationsFound(@PathVariable Optional<String> scanType) {
		LOG.debug("GET /rest/metrics/violations-found scanType=" + scanType);
		List<ScanType> types =
				scanType.isPresent() ? Arrays.asList(getScanType(scanType.get()))
						: this.scanTypes;

		return ResponseEntity
				.ok(getTopLevelMetric((metricsCacheService::getViolationCount), types));
	}

	@GetMapping(value = {"/average-scan-time", "/average-scan-time/{scanType}"})
	public ResponseEntity<JSONObject> getAverageScanTime(@PathVariable Optional<String> scanType) {
		LOG.debug("GET /rest/metrics/average-scan-time scanType=" + scanType);
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

	private JSONObject range(LocalDate start, LocalDate end, Supplier<JSONObject> preset,
			BiFunction<LocalDate, LocalDate, JSONObject> custom) {
		if (start == null && end == null) return preset.get();
		if (start == null || end == null) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
					"Both start and end dates are required");
		}
		try {
			return custom.apply(start, end);
		} catch (IllegalArgumentException e) {
			LOG.debug("Rejected metrics date range", e);
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid date range", e);
		}
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
