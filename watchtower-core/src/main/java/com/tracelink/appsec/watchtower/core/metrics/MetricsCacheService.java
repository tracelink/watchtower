package com.tracelink.appsec.watchtower.core.metrics;

import com.tracelink.appsec.watchtower.core.metrics.bucketer.AbstractBucketer;
import com.tracelink.appsec.watchtower.core.metrics.bucketer.BucketIntervals;
import com.tracelink.appsec.watchtower.core.metrics.bucketer.BucketerTimePeriod;
import com.tracelink.appsec.watchtower.core.metrics.bucketer.SimpleBucketer;
import com.tracelink.appsec.watchtower.core.metrics.chart.AbstractChartGenerator;
import com.tracelink.appsec.watchtower.core.metrics.chart.ScansByPeriodChartGenerator;
import com.tracelink.appsec.watchtower.core.metrics.chart.ViolationsByPeriodAndTypeChartGenerator;
import com.tracelink.appsec.watchtower.core.metrics.chart.ViolationsByPeriodChartGenerator;
import com.tracelink.appsec.watchtower.core.metrics.chart.ViolationsByTypeChartGenerator;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanEntity;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanResultService;
import com.tracelink.appsec.watchtower.core.scan.ScanType;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.service.PRScanResultService;
import com.tracelink.appsec.watchtower.core.scan.upload.service.UploadScanResultService;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;
import net.minidev.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * This service handles asynchronously generating any needed metrics for our dashboards that might
 * take longer than a page refresh and serve them up as needed from a cache.
 *
 * @author csmith
 */
@Service
public class MetricsCacheService {

	private static final Logger LOG = LoggerFactory.getLogger(MetricsCacheService.class);

	private static final String KEY_VIO_BY_PERIOD = "violationsByPeriod";
	private static final String KEY_VIO_BY_TYPE = "violationsByType";
	private static final String KEY_VIO_BY_PERIOD_AND_TYPE = "violationsByPeriodAndType";
	private static final String KEY_SCANS_BY_PERIOD = "scansByPeriod";
	private static final String SCAN_COUNT = "scanCount";
	private static final String VIO_COUNT = "violationCount";
	private static final String AVG_TIME = "averageTime";

	public static final String METRICS_NOT_READY =
			"Metrics are being generated and will be available soon";

	private final Map<ScanType, AbstractScanResultService<?, ?>> serviceMap;

	// Initialized empty so that if the first update takes longer than a user can
	// log in, they don't see anything, but nothing breaks
	private Map<CacheKey, JSONObject> chartsCache = new HashMap<>();
	private Map<CacheKey, Number> statsCache = new HashMap<>();

	private final ReentrantLock pauseLock = new ReentrantLock();
	private final Condition unPaused = pauseLock.newCondition();
	private boolean metricsReady = false;
	private volatile boolean isPaused = false;

	public MetricsCacheService(@Autowired PRScanResultService prScanResultService,
			@Autowired UploadScanResultService uploadScanResultService) {
		this.serviceMap = new HashMap<>();
		this.serviceMap.put(ScanType.PULL_REQUEST, prScanResultService);
		this.serviceMap.put(ScanType.UPLOAD, uploadScanResultService);
	}

	/**
	 * Marked only after the first time the metrics are generated
	 *
	 * @return true if the metrics have been generated fully at least once
	 */
	public boolean isMetricsCacheReady() {
		return this.metricsReady;
	}

	/**
	 * Pause metrics gathering
	 */
	public void pause() {
		pauseLock.lock();
		try {
			isPaused = true;
		} finally {
			pauseLock.unlock();
		}
	}

	/**
	 * Unpause metrics gathering
	 */
	public void resume() {
		pauseLock.lock();
		try {
			isPaused = false;
			unPaused.signalAll();
		} finally {
			pauseLock.unlock();
		}
	}


	/**
	 * Periodically, asynchronously update all metrics in the system.
	 */
	@Scheduled(initialDelay = 1000 * 5, fixedDelay = 1000L * 60)
	public void updateAllMetrics() {
		pauseLock.lock();
		try {
			while (isPaused) {
				unPaused.await();
			}
		} catch (InterruptedException ie) {
			return;
		} finally {
			pauseLock.unlock();
		}
		try {
			LOG.info("Beginning periodic update of metrics");
			Map<CacheKey, JSONObject> chartsMap = new HashMap<>();
			Map<CacheKey, Number> statsMap = new HashMap<>();
			for (ScanType type : this.serviceMap.keySet()) {
				LOG.debug("Starting scanType: " + type.getDisplayName());

				// Charts cache updates
				for (BucketerTimePeriod period : BucketerTimePeriod.values()) {
					LOG.debug("Starting time period: " + period);
					Map<String, AbstractChartGenerator<AbstractScanEntity<?, ?>, ?>> chartGenerators = new HashMap<>();
					chartGenerators.put(KEY_VIO_BY_PERIOD, new ViolationsByPeriodChartGenerator());
					chartGenerators.put(KEY_VIO_BY_TYPE, new ViolationsByTypeChartGenerator());
					chartGenerators.put(KEY_VIO_BY_PERIOD_AND_TYPE,
							new ViolationsByPeriodAndTypeChartGenerator());
					chartGenerators.put(KEY_SCANS_BY_PERIOD, new ScansByPeriodChartGenerator());

					// Get datasets for all charts of this type and period
					Map<String, JSONObject> chartDatasets = generateCharts(type, period,
							chartGenerators);
					// Add all charts to the map with an appropriate cache key
					chartDatasets.forEach((k, v) -> {
						CacheKey key = new CacheKey(type, k, period.getPeriod());
						chartsMap.put(key, v);
					});
				}

				// Stats cache updates
				LOG.debug("Starting getAverageTime");
				CacheKey avgTimeKey = new CacheKey(type, AVG_TIME);
				statsMap.put(avgTimeKey, this.serviceMap.get(type).getAverageTime());
				LOG.debug("Starting countScans");
				CacheKey scansKey = new CacheKey(type, SCAN_COUNT);
				statsMap.put(scansKey, this.serviceMap.get(type).countScans());
				LOG.debug("Starting countViolations");
				CacheKey violationsKey = new CacheKey(type, VIO_COUNT);
				statsMap.put(violationsKey, this.serviceMap.get(type).countViolations());
			}
			this.chartsCache = chartsMap;
			this.statsCache = statsMap;
			LOG.info("Periodic update of metrics complete");
			this.metricsReady = true;
		} catch (Exception e) {
			LOG.error("Periodic update of metrics failed with an exception", e);
		}
	}

	/**
	 * Gets metrics about the number of violations of each type found within a certain length of
	 * time.
	 *
	 * @param type   the ScanType to retrieve
	 * @param period a string representing a certain length of time over which to gather metrics
	 * @return map containing labels for each violation type and a dataset for number of violations
	 * of each type
	 */
	public JSONObject getViolationsByType(ScanType type, String period) {
		return getMetric(type, KEY_VIO_BY_TYPE, period);
	}

	/**
	 * Gets metrics about the number of violations of found within a certain length of time. Data is
	 * divided into time periods of appropriate length.
	 *
	 * @param type   the ScanType to retrieve
	 * @param period a string representing a certain length of time over which to gather metrics
	 * @return map containing labels for each subdivided time period and a dataset for number of
	 * violations found during each period
	 */
	public JSONObject getViolationsByPeriod(ScanType type, String period) {
		return getMetric(type, KEY_VIO_BY_PERIOD, period);
	}

	/**
	 * Gets metrics about the number of violations of each type found within a certain length of
	 * time. Data is divided into time periods of appropriate length.
	 *
	 * @param type   the ScanType to retrieve
	 * @param period a string representing a certain length of time over which to gather metrics
	 * @return map containing labels for each subdivided time period and datasets for number of
	 * violations found during each period for each violation type
	 */
	public JSONObject getViolationsByPeriodAndType(ScanType type, String period) {
		return getMetric(type, KEY_VIO_BY_PERIOD_AND_TYPE, period);
	}

	/**
	 * Gets metrics about the number of scans completed within a certain length of time. Data is
	 * divided into time periods of appropriate length.
	 *
	 * @param type   the ScanType to retrieve
	 * @param period a string representing a certain length of time over which to gather metrics
	 * @return map containing labels for each subdivided time period and a dataset for number of
	 * scans completed during each period
	 */
	public JSONObject getScansByPeriod(ScanType type, String period) {
		return getMetric(type, KEY_SCANS_BY_PERIOD, period);
	}

	/**
	 * Generates chart data for metrics about scans and violations from the database over a given
	 * period of time using the given chart generators.
	 *
	 * @param type            the ScanType to retrieve
	 * @param period          a {@link BucketerTimePeriod} representing the period of time over
	 *                        which to gather metrics
	 * @param chartGenerators map of chart generators to format scan and violation metrics
	 * @return map from string to JSON object, where the string is a cache key (e.g.
	 * KEY_VIO_BY_TYPE) and the JSON object contains labels and datasets for a metrics chart
	 */
	private Map<String, JSONObject> generateCharts(ScanType type, BucketerTimePeriod period,
			Map<String, AbstractChartGenerator<AbstractScanEntity<?, ?>, ?>> chartGenerators) {
		// Create bucketer
		AbstractBucketer<AbstractScanEntity<?, ?>> bucketer = new SimpleBucketer<>(
				period, () -> serviceMap.get(type).getOldestScanDate().atStartOfDay(),
				AbstractScanEntity::getEndDate);
		// Get start and end dates of buckets
		BucketIntervals bucketIntervals = bucketer.getBucketIntervals();
		long startMillis = bucketIntervals.getStart().toInstant(ZoneOffset.UTC)
				.toEpochMilli();
		long endMillis = bucketIntervals.getEnd().toInstant(ZoneOffset.UTC)
				.toEpochMilli();
		// Get scans iterator and iterate through all pages of scans
		Iterator<Page<AbstractScanEntity<?, ?>>> pageIterator = serviceMap.get(type)
				.scanIteratorBetweenDates(startMillis, endMillis);
		pageIterator.forEachRemaining(
				page -> {
					if (page.getNumber() % 5 == 0) {
						LOG.debug("Generating metrics for page: " + page.getNumber());
					}
					// Bucket scans
					List<List<AbstractScanEntity<?, ?>>> bucketedScans = bucketer
							.putItemsInBuckets(page.getContent());
					// Reduce this page of results for each chart generator
					chartGenerators.values()
							.forEach(chartGenerator -> chartGenerator.reduce(bucketedScans));
				});

		List<String> labels = bucketIntervals.getLabels();
		return chartGenerators.entrySet().stream().collect(
				Collectors.toMap(Map.Entry::getKey, entry -> entry.getValue().getResults(labels)));
	}

	private JSONObject getMetric(ScanType type, String key, String period) {
		JSONObject json;
		try {
			// Ensure period is valid
			BucketerTimePeriod.ofPeriod(period);
			CacheKey cacheKey = new CacheKey(type, key, period);
			json = chartsCache.get(cacheKey);
		} catch (IllegalArgumentException e) {
			json = new JSONObject();
			json.put("error", Collections.singletonList(e.getMessage()));
		}
		if (json == null) {
			json = new JSONObject();
			json.put("error", "Null metric for that period");
		}
		return json;
	}

	/**
	 * Get the count of scans for the scan type
	 *
	 * @param type the ScanType to retrieve
	 * @return the scan count for this type
	 */
	public long getScanCount(ScanType type) {
		CacheKey key = new CacheKey(type, SCAN_COUNT);
		return (long) this.statsCache.getOrDefault(key, 0L);
	}

	/**
	 * Get the count of violations for the scan type
	 *
	 * @param type the ScanType to retrieve
	 * @return the violation count for this type
	 */
	public long getViolationCount(ScanType type) {
		CacheKey key = new CacheKey(type, VIO_COUNT);
		return (long) this.statsCache.getOrDefault(key, 0L);
	}

	/**
	 * Get the average of scan durations for the scan type in milliseconds
	 *
	 * @param type the ScanType to retrieve
	 * @return the average scan duration for this type
	 */
	public double getAverageScanTime(ScanType type) {
		CacheKey key = new CacheKey(type, AVG_TIME);
		return (double) this.statsCache.getOrDefault(key, 0.0);
	}

	/**
	 * Get the average of scan durations for the scan type expressed in ms, s, or mins, whichever
	 * provides the best resolution
	 *
	 * @param type the ScanType to retrieve
	 * @return the average scan duration in the best resolution
	 */
	public String getAverageScanTimeString(ScanType type) {
		double slicer = getAverageScanTime(type);
		if (slicer < 1000) {
			return String.format("%.0f ms", slicer);
		}
		slicer /= 1000;
		if (slicer < 60) {
			return String.format("%.2f s", slicer);
		}
		slicer /= 60;
		return String.format("%.2f mins", slicer);
	}

	private static class CacheKey {

		private final String generatedKey;

		CacheKey(ScanType type, String key) {
			this.generatedKey = type.getTypeName() + "-" + key;
		}

		CacheKey(ScanType type, String key, String period) {
			this.generatedKey = type.getTypeName() + "-" + key + "-" + period;
		}

		public int hashCode() {
			return this.generatedKey.hashCode();
		}

		public boolean equals(Object other) {
			return (other instanceof CacheKey)
					&& ((CacheKey) other).generatedKey.equals(this.generatedKey);
		}
	}

}
