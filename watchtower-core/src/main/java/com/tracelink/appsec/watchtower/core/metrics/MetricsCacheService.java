package com.tracelink.appsec.watchtower.core.metrics;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Function;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import com.tracelink.appsec.watchtower.core.metrics.MetricsProjectionRepository.DailyScanMetric;
import com.tracelink.appsec.watchtower.core.metrics.MetricsProjectionRepository.DailyViolationMetric;
import com.tracelink.appsec.watchtower.core.metrics.MetricsProjectionRepository.ScannerTimingMetric;
import com.tracelink.appsec.watchtower.core.metrics.bucketer.BucketIntervals;
import com.tracelink.appsec.watchtower.core.metrics.bucketer.BucketerTimePeriod;
import com.tracelink.appsec.watchtower.core.metrics.bucketer.SimpleBucketer;
import com.tracelink.appsec.watchtower.core.scan.ScanType;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestSyncSettingsEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanPerformanceSummary;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.service.PullRequestSyncSettingsService;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanType;
import com.tracelink.appsec.watchtower.core.scan.presentation.DurationText;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummaryCodec;

import net.minidev.json.JSONObject;

/** Dashboard metrics facade backed by durable daily database projections. */
@Service
public class MetricsCacheService {
	public static final String METRICS_NOT_READY = "Metrics are not available";

	private final MetricsProjectionRepository projections;
	private final PullRequestSyncSettingsService settingsService;
	private final ZoneId metricsZone;

	@Autowired
	public MetricsCacheService(MetricsProjectionRepository projections,
			PullRequestSyncSettingsService settingsService,
			@Value("${watchtower.metrics.zone:UTC}") String metricsZone) {
		this.projections = projections;
		this.settingsService = settingsService;
		this.metricsZone = ZoneId.of(metricsZone);
	}

	MetricsCacheService(MetricsProjectionRepository projections,
			PullRequestSyncSettingsService settingsService) {
		this(projections, settingsService, ZoneId.systemDefault().getId());
	}

	public boolean isMetricsCacheReady() { return true; }
	public void pause() { }
	public void resume() { }

	/** Compatibility hook; projections update when scan results are persisted. */
	@Deprecated(forRemoval = true)
	public void updateAllMetrics() { }

	public JSONObject getViolationsByType(ScanType type, String period) {
		Buckets buckets = buckets(type, period);
		Map<String, Long> totals = new TreeMap<>();
		bucketViolations(type, buckets).forEach(bucket -> bucket.forEach(
				metric -> totals.merge(metric.name(), metric.count(), Long::sum)));
		JSONObject result = new JSONObject();
		result.put("labels", new ArrayList<>(totals.keySet()));
		result.put("counts", new ArrayList<>(totals.values()));
		return result;
	}

	public JSONObject getViolationsByPeriod(ScanType type, String period) {
		Buckets buckets = buckets(type, period);
		JSONObject result = base(buckets);
		result.put("counts", type == CodeScanType.REPOSITORY
				? bucketViolations(type, buckets).stream()
						.map(bucket -> bucket.stream().mapToLong(DailyViolationMetric::count).sum()).toList()
				: bucketScans(type, buckets).stream()
						.map(bucket -> bucket.stream().mapToLong(DailyScanMetric::violations).sum()).toList());
		return result;
	}

	public JSONObject getViolationsByPeriodAndType(ScanType type, String period) {
		Buckets buckets = buckets(type, period);
		List<Map<String, Long>> values = bucketViolations(type, buckets).stream().map(bucket -> {
			Map<String, Long> map = new TreeMap<>();
			bucket.forEach(metric -> map.merge(metric.name(), metric.count(), Long::sum));
			return map;
		}).toList();
		JSONObject result = base(buckets);
		values.stream().flatMap(map -> map.keySet().stream()).distinct().sorted().forEach(name ->
				result.put(name, values.stream().map(map -> map.getOrDefault(name, 0L)).toList()));
		return result;
	}

	public JSONObject getScansByPeriod(ScanType type, String period) {
		Buckets buckets = buckets(type, period);
		JSONObject result = base(buckets);
		result.put("counts", bucketScans(type, buckets).stream()
				.map(bucket -> bucket.stream().mapToLong(DailyScanMetric::scans).sum()).toList());
		if (buckets.period() == BucketerTimePeriod.ALL_TIME) {
			long impossible = projections.implausibleScanCount(type.getTypeName());
			if (impossible > 0) {
				result.put("impossibleDates", impossible);
				result.put("impossibleBefore", LocalDate.ofInstant(Instant.ofEpochMilli(
						MetricsProjectionRepository.EARLIEST_PLAUSIBLE_SCAN_MILLIS), ZoneOffset.UTC).toString());
			}
		}
		return result;
	}

	public JSONObject getSourceSizeByPeriod(ScanType type, String period) {
		Buckets buckets = buckets(type, period);
		JSONObject result = base(buckets);
		result.put("counts", bucketScans(type, buckets).stream().map(bucket -> {
			long count = bucket.stream().mapToLong(DailyScanMetric::sourceSizeCount).sum();
			long sum = bucket.stream().mapToLong(DailyScanMetric::sourceSizeSum).sum();
			return count == 0 ? 0D : (double) sum / count;
		}).toList());
		return result;
	}

	public JSONObject getPrPerformanceByPeriod(String period) {
		Buckets buckets = buckets(CodeScanType.PULL_REQUEST, period);
		JSONObject result = performanceResult(labels(buckets),
				bucketScans(CodeScanType.PULL_REQUEST, buckets));
		result.put("scannerSeries", scannerSeries(bucketScannerTimings(buckets)));
		return result;
	}

	/** Average elapsed time of completed scans, from the existing daily duration projection. */
	public JSONObject getScanDurationByPeriod(ScanType type, String period) {
		Buckets buckets = buckets(type, period);
		return scanDurationResult(labels(buckets), bucketScans(type, buckets));
	}

	public JSONObject getViolationsByType(ScanType type, LocalDate start, LocalDate end) {
		CustomBuckets buckets = customBuckets(start, end);
		Map<String, Long> totals = new TreeMap<>();
		customViolations(type, buckets).forEach(bucket -> bucket.forEach(
				metric -> totals.merge(metric.name(), metric.count(), Long::sum)));
		JSONObject result = new JSONObject();
		result.put("labels", new ArrayList<>(totals.keySet()));
		result.put("counts", new ArrayList<>(totals.values()));
		return result;
	}

	public JSONObject getViolationsByPeriod(ScanType type, LocalDate start, LocalDate end) {
		CustomBuckets buckets = customBuckets(start, end);
		if (type == CodeScanType.REPOSITORY) {
			JSONObject result = customBase(buckets);
			result.put("counts", customViolations(type, buckets).stream()
					.map(bucket -> bucket.stream().mapToLong(DailyViolationMetric::count).sum()).toList());
			return result;
		}
		return customScanResult(type, buckets,
				bucket -> bucket.stream().mapToLong(DailyScanMetric::violations).sum());
	}

	public JSONObject getScansByPeriod(ScanType type, LocalDate start, LocalDate end) {
		CustomBuckets buckets = customBuckets(start, end);
		return customScanResult(type, buckets,
				bucket -> bucket.stream().mapToLong(DailyScanMetric::scans).sum());
	}

	public JSONObject getSourceSizeByPeriod(ScanType type, LocalDate start, LocalDate end) {
		CustomBuckets buckets = customBuckets(start, end);
		return customScanResult(type, buckets, bucket -> {
			long count = bucket.stream().mapToLong(DailyScanMetric::sourceSizeCount).sum();
			return count == 0 ? 0D : bucket.stream().mapToLong(DailyScanMetric::sourceSizeSum).sum()
					/ (double) count;
		});
	}

	public JSONObject getPrPerformanceByPeriod(LocalDate start, LocalDate end) {
		CustomBuckets buckets = customBuckets(start, end);
		JSONObject result = performanceResult(buckets.labels(),
				customScans(CodeScanType.PULL_REQUEST, buckets));
		result.put("scannerSeries", scannerSeries(group(
				projections.findPrScannerTimings(startOfDay(start), startOfDay(end.plusDays(1))),
				ScannerTimingMetric::date, buckets)));
		return result;
	}

	public JSONObject getScanDurationByPeriod(ScanType type, LocalDate start, LocalDate end) {
		CustomBuckets buckets = customBuckets(start, end);
		return scanDurationResult(buckets.labels(), customScans(type, buckets));
	}

	public JSONObject getViolationsByPeriodAndType(ScanType type, LocalDate start, LocalDate end) {
		CustomBuckets buckets = customBuckets(start, end);
		List<Map<String, Long>> values = customViolations(type, buckets).stream().map(bucket -> {
			Map<String, Long> map = new TreeMap<>();
			bucket.forEach(metric -> map.merge(metric.name(), metric.count(), Long::sum));
			return map;
		}).toList();
		JSONObject result = customBase(buckets);
		values.stream().flatMap(map -> map.keySet().stream()).distinct().sorted().forEach(name ->
				result.put(name, values.stream().map(map -> map.getOrDefault(name, 0L)).toList()));
		return result;
	}

	public long getScanCount(ScanType type) {
		return projections.sum(type.getTypeName(), "scan_count");
	}

	public long getScanCountToday(ScanType type) {
		long today = LocalDate.now(metricsZone).atStartOfDay(metricsZone).toInstant()
				.toEpochMilli();
		return projections.findScans(type.getTypeName(), today,
				today + Duration.ofDays(1).toMillis()).stream().mapToLong(DailyScanMetric::scans).sum();
	}

	public long getViolationCount(ScanType type) {
		long local = projections.sum(type.getTypeName(), "violation_count");
		return type == CodeScanType.REPOSITORY
				? local + projections.repositoryProviderFindingCount(0, Long.MAX_VALUE) : local;
	}

	public HomeMetricsSnapshot getHomeMetrics(long start, long end) {
		long completed = 0;
		long findings = 0;
		long durationSum = 0;
		long durationCount = 0;
		for (ScanType type : List.of(CodeScanType.PULL_REQUEST, CodeScanType.UPLOAD,
				CodeScanType.REPOSITORY, ImageScanType.CONTAINER)) {
			for (DailyScanMetric metric : projections.findScans(type.getTypeName(), start, end)) {
				completed += metric.scans();
				findings += metric.violations();
				durationSum += metric.durationSum();
				durationCount += metric.durationCount();
			}
		}
		findings += projections.repositoryProviderFindingCount(start, end);
		double average = durationCount == 0 ? 0 : (double) durationSum / durationCount;
		return new HomeMetricsSnapshot(completed, findings, average);
	}

	public double getAverageScanTime(ScanType type) {
		return projections.average(type.getTypeName(), "duration_sum_ms", "duration_count");
	}

	public String getAverageScanTimeString(ScanType type) {
		return formatDuration(getAverageScanTime(type));
	}

	public double getAverageSourceSize(ScanType type) {
		return projections.average(type.getTypeName(), "source_size_sum_bytes", "source_size_count");
	}

	public String getAverageSourceSizeString(ScanType type) {
		double size = getAverageSourceSize(type);
		if (size < 1024) return String.format("%.0f B", size);
		size /= 1024;
		if (size < 1024) return String.format("%.2f KB", size);
		return String.format("%.2f MB", size / 1024);
	}

	public long getPullRequestCount() { return projections.dimension("pull_request_count"); }
	public long getRepositoryCount() { return projections.dimension("repository_count"); }

	public PRScanPerformanceSummary getRecentPrPerformance() {
		return projections.performanceSince(System.currentTimeMillis()
				- Duration.ofDays(getPrPerformanceWindowDays()).toMillis());
	}

	public PRScanPerformanceSummary getAllTimePrPerformance() {
		return projections.performanceSince(0);
	}

	public int getPrPerformanceWindowDays() {
		PullRequestSyncSettingsEntity settings = settingsService.getSettings();
		return settings == null ? 7 : settings.getPerformanceWindowDays();
	}

	private Buckets buckets(ScanType type, String value) {
		BucketerTimePeriod period = BucketerTimePeriod.ofPeriod(value);
		SimpleBucketer<DailyScanMetric> bucketer = new SimpleBucketer<>(period,
				() -> projections.oldestDate(type.getTypeName()), DailyScanMetric::date);
		return new Buckets(period, bucketer, bucketer.getBucketIntervals());
	}

	private List<List<DailyScanMetric>> bucketScans(ScanType type, Buckets buckets) {
		long start = millis(buckets.intervals().getStart());
		long end = millis(buckets.intervals().getEnd());
		return buckets.scans().putItemsInBuckets(projections.findScans(type.getTypeName(), start, end));
	}

	private List<List<DailyViolationMetric>> bucketViolations(ScanType type, Buckets buckets) {
		SimpleBucketer<DailyViolationMetric> bucketer = new SimpleBucketer<>(buckets.period(),
				() -> projections.oldestDate(type.getTypeName()), DailyViolationMetric::date);
		return bucketer.putItemsInBuckets(projections.findViolations(type.getTypeName(),
				millis(buckets.intervals().getStart()), millis(buckets.intervals().getEnd())));
	}

	private JSONObject base(Buckets buckets) {
		JSONObject result = new JSONObject();
		result.put("labels", labels(buckets));
		return result;
	}

	private List<String> labels(Buckets buckets) {
		if (buckets.period() != BucketerTimePeriod.LAST_THIRTY_DAYS) {
			return buckets.intervals().getLabels();
		}
		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd MMM", Locale.ENGLISH);
		List<java.time.LocalDateTime> boundaries = buckets.intervals().getBuckets();
		return boundaries.subList(0, boundaries.size() - 1).stream()
				.map(date -> date.format(formatter)).toList();
	}

	private List<List<ScannerTimingMetric>> bucketScannerTimings(Buckets buckets) {
		SimpleBucketer<ScannerTimingMetric> bucketer = new SimpleBucketer<>(buckets.period(),
				() -> projections.oldestDate(CodeScanType.PULL_REQUEST.getTypeName()),
				ScannerTimingMetric::date);
		return bucketer.putItemsInBuckets(projections.findPrScannerTimings(
				millis(buckets.intervals().getStart()), millis(buckets.intervals().getEnd())));
	}

	private List<Map<String, Object>> scannerSeries(List<List<ScannerTimingMetric>> buckets) {
		List<Map<String, long[]>> bucketValues = new ArrayList<>();
		java.util.Set<String> scannerNames = new java.util.TreeSet<>();
		for (List<ScannerTimingMetric> bucket : buckets) {
			Map<String, long[]> values = new TreeMap<>();
			for (ScannerTimingMetric metric : bucket) {
				ScanExecutionSummaryCodec.decode(metric.timingsJson()).forEach(scanner -> {
					long[] aggregate = values.computeIfAbsent(scanner.scannerName(), key -> new long[2]);
					aggregate[0] += scanner.durationMs();
					aggregate[1]++;
					scannerNames.add(scanner.scannerName());
				});
			}
			bucketValues.add(values);
		}
		List<Map<String, Object>> result = new ArrayList<>();
		for (String scannerName : scannerNames) {
			Map<String, Object> series = new LinkedHashMap<>();
			series.put("name", scannerName);
			series.put("values", bucketValues.stream().map(values -> {
				long[] aggregate = values.get(scannerName);
				return aggregate == null || aggregate[1] == 0
						? 0D : aggregate[0] / (double) aggregate[1];
			}).toList());
			result.add(series);
		}
		return result;
	}

	private CustomBuckets customBuckets(LocalDate start, LocalDate end) {
		if (start == null || end == null || start.isAfter(end)) {
			throw new IllegalArgumentException("Start date must be on or before end date");
		}
		if (Duration.between(start.atStartOfDay(), end.plusDays(1).atStartOfDay()).toDays() > 3660) {
			throw new IllegalArgumentException("Custom date range cannot exceed 10 years");
		}
		long days = end.toEpochDay() - start.toEpochDay() + 1;
		Function<LocalDate, LocalDate> next = days <= 31 ? date -> date.plusDays(1)
				: days <= 180 ? date -> date.plusWeeks(1) : date -> date.plusMonths(1);
		List<LocalDate> boundaries = new ArrayList<>();
		for (LocalDate date = start; !date.isAfter(end); date = next.apply(date)) boundaries.add(date);
		boundaries.add(end.plusDays(1));
		List<String> labels = new ArrayList<>();
		for (int i = 0; i < boundaries.size() - 1; i++) {
			LocalDate from = boundaries.get(i);
			LocalDate to = boundaries.get(i + 1).minusDays(1);
			labels.add(from.equals(to) ? from.toString() : from + " – " + to);
		}
		return new CustomBuckets(boundaries, labels);
	}

	private List<List<DailyScanMetric>> customScans(ScanType type, CustomBuckets buckets) {
		List<DailyScanMetric> rows = projections.findScans(type.getTypeName(),
				startOfDay(buckets.boundaries().get(0)),
				startOfDay(buckets.boundaries().getLast()));
		return group(rows, DailyScanMetric::date, buckets);
	}

	private List<List<DailyViolationMetric>> customViolations(ScanType type, CustomBuckets buckets) {
		List<DailyViolationMetric> rows = projections.findViolations(type.getTypeName(),
				startOfDay(buckets.boundaries().get(0)),
				startOfDay(buckets.boundaries().getLast()));
		return group(rows, DailyViolationMetric::date, buckets);
	}

	private <T> List<List<T>> group(List<T> rows, Function<T, java.time.LocalDateTime> date,
			CustomBuckets buckets) {
		List<List<T>> grouped = new ArrayList<>();
		for (int i = 0; i < buckets.labels().size(); i++) grouped.add(new ArrayList<>());
		for (T row : rows) {
			LocalDate rowDate = date.apply(row).toLocalDate();
			for (int i = 0; i < grouped.size(); i++) {
				if (!rowDate.isBefore(buckets.boundaries().get(i))
						&& rowDate.isBefore(buckets.boundaries().get(i + 1))) {
					grouped.get(i).add(row);
					break;
				}
			}
		}
		return grouped;
	}

	private JSONObject customScanResult(ScanType type, CustomBuckets buckets,
			Function<List<DailyScanMetric>, Number> value) {
		JSONObject result = customBase(buckets);
		result.put("counts", customScans(type, buckets).stream().map(value).toList());
		return result;
	}

	private JSONObject customBase(CustomBuckets buckets) {
		JSONObject result = new JSONObject();
		result.put("labels", buckets.labels());
		return result;
	}

	private JSONObject performanceResult(List<String> labels,
			List<List<DailyScanMetric>> buckets) {
		JSONObject result = new JSONObject();
		result.put("labels", labels);
		result.put("samples", buckets.stream().map(bucket -> bucket.stream()
				.mapToLong(DailyScanMetric::performanceCount).sum()).toList());
		result.put("totalMs", performanceAverages(buckets, DailyScanMetric::totalDurationSum));
		result.put("sourceMs", performanceAverages(buckets, DailyScanMetric::sourceDurationSum));
		result.put("scannersMs", performanceAverages(buckets, DailyScanMetric::scannerDurationSum));
		result.put("processingMs", performanceAverages(buckets,
				DailyScanMetric::processingDurationSum));
		return result;
	}

	private JSONObject scanDurationResult(List<String> labels, List<List<DailyScanMetric>> buckets) {
		JSONObject result = new JSONObject();
		result.put("labels", labels);
		result.put("samples", buckets.stream().map(bucket -> bucket.stream()
				.mapToLong(DailyScanMetric::durationCount).sum()).toList());
		result.put("totalMs", buckets.stream().map(bucket -> {
			long count = bucket.stream().mapToLong(DailyScanMetric::durationCount).sum();
			return count == 0 ? 0D : bucket.stream().mapToLong(DailyScanMetric::durationSum).sum()
					/ (double) count;
		}).toList());
		return result;
	}

	private List<Double> performanceAverages(List<List<DailyScanMetric>> buckets,
			java.util.function.ToLongFunction<DailyScanMetric> value) {
		return buckets.stream().map(bucket -> {
			long count = bucket.stream().mapToLong(DailyScanMetric::performanceCount).sum();
			return count == 0 ? 0D : bucket.stream().mapToLong(value).sum() / (double) count;
		}).toList();
	}

	private long startOfDay(LocalDate date) {
		return date.atStartOfDay(metricsZone).toInstant().toEpochMilli();
	}

	private long millis(java.time.LocalDateTime date) {
		return date.atZone(metricsZone).toInstant().toEpochMilli();
	}

	private static String formatDuration(double millis) {
		return DurationText.of(millis);
	}

	private record Buckets(BucketerTimePeriod period, SimpleBucketer<DailyScanMetric> scans,
			BucketIntervals intervals) { }
	private record CustomBuckets(List<LocalDate> boundaries, List<String> labels) { }
}
