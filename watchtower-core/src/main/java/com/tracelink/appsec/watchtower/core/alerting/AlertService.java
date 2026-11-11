package com.tracelink.appsec.watchtower.core.alerting;

import java.time.Clock;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.alerting.entity.AlertDedupeEntity;
import com.tracelink.appsec.watchtower.core.alerting.entity.AlertLogEntity;
import com.tracelink.appsec.watchtower.core.alerting.entity.AlertRouteEntity;
import com.tracelink.appsec.watchtower.core.alerting.repository.AlertDedupeRepository;
import com.tracelink.appsec.watchtower.core.alerting.repository.AlertLogRepository;
import com.tracelink.appsec.watchtower.core.alerting.repository.AlertRouteRepository;

import io.micrometer.core.instrument.MeterRegistry;

/**
 * Turns raised events into queued messages, per the routes admins configured in Alert Settings.
 * {@link #raise(AlertEvent)} only writes to the database - the {@link AlertDeliveryWorker} does
 * the sending - and never throws, so raising an alert can never fail or slow down a scan.
 *
 * @author Watchtower
 */
@Service
public class AlertService {

	private static final Logger LOG = LoggerFactory.getLogger(AlertService.class);

	static final String METRIC = "watchtower.alerts";

	static final int MAX_ITEMS_PER_MESSAGE = 25;

	private static final long MILLIS_PER_HOUR = 3_600_000L;

	private final AlertTypeRegistry registry;

	private final AlertRouteRepository routeRepository;

	private final AlertLogRepository logRepository;

	private final AlertDedupeRepository dedupeRepository;

	private final Clock clock;

	private final MeterRegistry meterRegistry;

	@Autowired
	public AlertService(AlertTypeRegistry registry, AlertRouteRepository routeRepository,
			AlertLogRepository logRepository, AlertDedupeRepository dedupeRepository,
			ObjectProvider<MeterRegistry> meterRegistry) {
		this(registry, routeRepository, logRepository, dedupeRepository, Clock.systemUTC(),
				meterRegistry.getIfAvailable());
	}

	AlertService(AlertTypeRegistry registry, AlertRouteRepository routeRepository,
			AlertLogRepository logRepository, AlertDedupeRepository dedupeRepository, Clock clock,
			MeterRegistry meterRegistry) {
		this.registry = registry;
		this.routeRepository = routeRepository;
		this.logRepository = logRepository;
		this.dedupeRepository = dedupeRepository;
		this.clock = clock;
		this.meterRegistry = meterRegistry;
	}

	/**
	 * Queues the event's new items for every matching route.
	 *
	 * @param event what happened
	 */
	public void raise(AlertEvent event) {
		try {
			raiseToRoutes(event);
		} catch (RuntimeException e) {
			LOG.error("Could not queue {} alert", event.type(), e);
			count("failed");
		}
	}

	/**
	 * @param type    the alert type
	 * @param itemKey the caller's item key
	 * @return the fixed-length key stored for dedupe
	 */
	static String dedupeKey(String type, String itemKey) {
		return AlertHashing.sha256(type + '\u0000' + itemKey);
	}

	private void raiseToRoutes(AlertEvent event) {
		if (registry.get(event.type()).isEmpty()) {
			LOG.warn("Ignoring alert of unregistered type {}", event.type());
			return;
		}
		long now = clock.millis();
		for (AlertRouteEntity route : routeRepository.findByAlertTypeAndEnabledTrue(event.type())) {
			if (route.getChannel() == null || !route.getChannel().isEnabled()
					|| !matches(route, event)) {
				continue;
			}
			long windowStart = now - route.getDedupeWindowHours() * MILLIS_PER_HOUR;
			List<AlertItem> fresh = event.items().stream()
					.filter(item -> meetsPriority(route, item))
					.filter(item -> !dedupeRepository.existsByRouteIdAndDedupeKeyAndCreatedAtGreaterThan(
							route.getId(), dedupeKey(event.type(), item.dedupeKey()), windowStart))
					.toList();
			if (fresh.isEmpty()) {
				count("deduped");
				continue;
			}
			dedupeRepository.saveAll(fresh.stream().map(item -> new AlertDedupeEntity(
					route.getId(), dedupeKey(event.type(), item.dedupeKey()), now)).toList());
			if (route.getAggregation() == AlertAggregation.PER_FINDING) {
				fresh.forEach(item -> enqueue(route, event, List.of(item), now));
			} else {
				enqueue(route, event, fresh, now);
			}
		}
	}

	private static boolean matches(AlertRouteEntity route, AlertEvent event) {
		if (StringUtils.isNotBlank(route.getApiLabelFilter())
				&& !route.getApiLabelFilter().trim().equalsIgnoreCase(event.apiLabel())) {
			return false;
		}
		List<Pattern> include = globs(route.getRepoInclude());
		if (!include.isEmpty() && !anyMatch(include, event.repoName())) {
			return false;
		}
		return !anyMatch(globs(route.getRepoExclude()), event.repoName());
	}

	private static boolean meetsPriority(AlertRouteEntity route, AlertItem item) {
		return route.getMinPriority() == null || item.priority() == null
				|| item.priority().compareTo(route.getMinPriority()) <= 0;
	}

	/** Comma-separated globs where {@code *} is the only wildcard; case-insensitive. */
	private static List<Pattern> globs(String globList) {
		return Arrays.stream(StringUtils.defaultString(globList).split(","))
				.map(String::trim).filter(glob -> !glob.isEmpty())
				.map(glob -> Pattern.compile(
						Arrays.stream(glob.split("\\*", -1)).map(Pattern::quote)
								.reduce((left, right) -> left + ".*" + right).orElse(""),
						Pattern.CASE_INSENSITIVE))
				.toList();
	}

	private static boolean anyMatch(List<Pattern> patterns, String value) {
		return value != null && patterns.stream().anyMatch(p -> p.matcher(value).matches());
	}

	private void enqueue(AlertRouteEntity route, AlertEvent event, List<AlertItem> items,
			long now) {
		AlertLogEntity message = new AlertLogEntity();
		message.setAlertType(event.type());
		message.setRouteId(route.getId());
		message.setChannelId(route.getChannel().getId());
		message.setThreadKey(event.threadKey());
		message.setStatus(AlertStatus.PENDING);
		message.setNextAttemptAt(now);
		message.setCreatedAt(now);
		message.setPayload(format(event, items));
		logRepository.save(message);
		count("queued");
	}

	/**
	 * Google Chat text: {@code *bold*} and {@code <url|label>} links.
	 */
	static String format(AlertEvent event, List<AlertItem> items) {
		StringBuilder text = new StringBuilder("*").append(event.title()).append('*');
		if (event.repoName() != null) {
			text.append("\nRepository: ").append(event.repoName());
		}
		items.stream().limit(MAX_ITEMS_PER_MESSAGE)
				.forEach(item -> text.append("\n• ").append(item.text()));
		if (items.size() > MAX_ITEMS_PER_MESSAGE) {
			text.append("\n…and ").append(items.size() - MAX_ITEMS_PER_MESSAGE).append(" more");
		}
		if (event.link() != null) {
			text.append("\n<").append(event.link()).append("|Open in Watchtower>");
		}
		return text.toString();
	}

	private void count(String outcome) {
		if (meterRegistry != null) {
			meterRegistry.counter(METRIC, "outcome", outcome.toLowerCase(Locale.ROOT)).increment();
		}
	}
}
