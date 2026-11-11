package com.tracelink.appsec.watchtower.core.alerting;

import java.util.Collection;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.alerting.entity.AlertChannelEntity;
import com.tracelink.appsec.watchtower.core.alerting.entity.AlertLogEntity;
import com.tracelink.appsec.watchtower.core.alerting.entity.AlertRouteEntity;
import com.tracelink.appsec.watchtower.core.alerting.repository.AlertChannelRepository;
import com.tracelink.appsec.watchtower.core.alerting.repository.AlertLogRepository;
import com.tracelink.appsec.watchtower.core.alerting.repository.AlertRouteRepository;
import com.tracelink.appsec.watchtower.core.encryption.model.EncryptionType;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/**
 * Backs the Alert Settings page. A channel's webhook URL is write-only: it is validated, stored
 * encrypted, and only ever shown masked. Every change is logged with who made it - never the URL.
 *
 * @author Watchtower
 */
@Service
public class AlertSettingsService {

	private static final Logger LOG = LoggerFactory.getLogger(AlertSettingsService.class);

	static final int MAX_NAME_LENGTH = 100;

	static final int MAX_FILTER_LENGTH = 1000;

	static final int MAX_DEDUPE_WINDOW_HOURS = 24 * 365;

	private static final Pattern NAME = Pattern.compile("[A-Za-z0-9 ._-]+");

	/** Repository globs: names, '*' and commas only. */
	private static final Pattern GLOB_LIST = Pattern.compile("[A-Za-z0-9._\\-*, ]*");

	private static final Pattern API_LABEL = Pattern.compile("[A-Za-z0-9._ -]*");

	/** A channel as the page may show it. */
	public record ChannelView(long id, String name, String maskedUrl, boolean enabled,
			Long lastTestAt, String lastTestStatus) {
	}

	/** A route as submitted. */
	public record RouteRequest(String alertType, long channelId, RulePriority minPriority,
			String apiLabelFilter, String repoInclude, String repoExclude,
			AlertAggregation aggregation, int dedupeWindowHours) {
	}

	private final AlertChannelRepository channelRepository;

	private final AlertRouteRepository routeRepository;

	private final AlertLogRepository logRepository;

	private final AlertTypeRegistry registry;

	private final GoogleChatSender sender;

	private final EncryptionType encryptionType;

	private final boolean production;

	@Autowired
	public AlertSettingsService(AlertChannelRepository channelRepository,
			AlertRouteRepository routeRepository, AlertLogRepository logRepository,
			AlertTypeRegistry registry, GoogleChatSender sender,
			@Value("${watchtower.encryption.type:none}") EncryptionType encryptionType,
			Environment environment) {
		this(channelRepository, routeRepository, logRepository, registry, sender, encryptionType,
				environment.acceptsProfiles(Profiles.of("prd")));
	}

	AlertSettingsService(AlertChannelRepository channelRepository,
			AlertRouteRepository routeRepository, AlertLogRepository logRepository,
			AlertTypeRegistry registry, GoogleChatSender sender, EncryptionType encryptionType,
			boolean production) {
		this.channelRepository = channelRepository;
		this.routeRepository = routeRepository;
		this.logRepository = logRepository;
		this.registry = registry;
		this.sender = sender;
		this.encryptionType = encryptionType;
		this.production = production;
	}

	public List<ChannelView> getChannels() {
		return channelRepository.findAll().stream()
				.map(channel -> new ChannelView(channel.getId(), channel.getName(),
						GoogleChatWebhook.mask(channel.getWebhookUrl()), channel.isEnabled(),
						channel.getLastTestAt(), channel.getLastTestStatus()))
				.toList();
	}

	public List<AlertRouteEntity> getRoutes() {
		return routeRepository.findAll();
	}

	/**
	 * One page of delivery history, newest first, filtered by status and alert type ("all" for
	 * either). Rejects unknown filters and pages over 100 rows.
	 */
	public com.tracelink.appsec.watchtower.core.mvc.PagedResult<AlertHistoryRow> history(String status, String type,
			int page, int size, java.util.Map<Long, String> channelNames) {
		boolean knownStatus = "all".equals(status)
				|| java.util.Arrays.stream(AlertStatus.values()).anyMatch(s -> s.name().equals(status));
		boolean knownType = "all".equals(type) || registry.getTypes().stream().anyMatch(t -> t.key().equals(type));
		if (!knownStatus || !knownType || page < 0 || size < 1 || size > 100) {
			throw new IllegalArgumentException("Choose a known status, alert type and page.");
		}
		var rows = logRepository.findHistory("all".equals(status) ? null : AlertStatus.valueOf(status),
				"all".equals(type) ? null : type, org.springframework.data.domain.PageRequest.of(page, size));
		return com.tracelink.appsec.watchtower.core.mvc.PagedResult.of(rows,
				log -> AlertHistoryRow.from(log, channelNames));
	}

	/**
	 * @return how many alert messages the history holds, for the History tab's count
	 */
	public long historyCount() {
		return logRepository.count();
	}

	public List<AlertLogEntity> getRecentAlerts() {
		return logRepository.findTop100ByOrderByIdDesc();
	}

	public Collection<AlertType> getAlertTypes() {
		return registry.getTypes();
	}

	/**
	 * @throws IllegalArgumentException with a user-facing reason if the channel is invalid
	 */
	public void addChannel(String rawName, String webhookUrl, String user) {
		requireEncryptedStorage();
		String name = validName(rawName);
		if (channelRepository.findByName(name) != null) {
			throw new IllegalArgumentException("A channel with that name already exists.");
		}
		AlertChannelEntity channel = new AlertChannelEntity();
		channel.setName(name);
		channel.setWebhookUrl(GoogleChatWebhook.validate(webhookUrl));
		channel.setCreatedBy(user);
		channel.setUpdatedBy(user);
		channel.setUpdatedAt(System.currentTimeMillis());
		channelRepository.save(channel);
		LOG.info("Alert channel '{}' added by {}", name, user);
	}

	/**
	 * @param webhookUrl a new URL, or blank to keep the stored one
	 * @throws IllegalArgumentException with a user-facing reason if the change is invalid
	 */
	public void updateChannel(long id, String rawName, String webhookUrl, boolean enabled,
			String user) {
		AlertChannelEntity channel = channel(id);
		String name = validName(rawName);
		AlertChannelEntity sameName = channelRepository.findByName(name);
		if (sameName != null && sameName.getId() != channel.getId()) {
			throw new IllegalArgumentException("A channel with that name already exists.");
		}
		if (StringUtils.isNotBlank(webhookUrl)) {
			requireEncryptedStorage();
			channel.setWebhookUrl(GoogleChatWebhook.validate(webhookUrl));
		}
		channel.setName(name);
		channel.setEnabled(enabled);
		channel.setUpdatedBy(user);
		channel.setUpdatedAt(System.currentTimeMillis());
		channelRepository.save(channel);
		LOG.info("Alert channel {} ('{}') updated by {}: enabled={} urlChanged={}", id, name,
				user, enabled, StringUtils.isNotBlank(webhookUrl));
	}

	public void deleteChannel(long id, String user) {
		AlertChannelEntity channel = channel(id);
		if (routeRepository.existsByChannel_Id(id)) {
			throw new IllegalArgumentException("Delete this channel's routes first.");
		}
		channelRepository.delete(channel);
		LOG.info("Alert channel {} ('{}') deleted by {}", id, channel.getName(), user);
	}

	/**
	 * Sends a test message now, bypassing the queue.
	 *
	 * @return the outcome, as shown on the page
	 */
	public String testChannel(long id, String user) {
		AlertChannelEntity channel = channel(id);
		GoogleChatSender.SendResult result = sender.send(channel.getWebhookUrl(),
				"*Watchtower test alert* sent by " + user + ". Alerts will arrive here.", null);
		String outcome = result.success() ? "Sent" : "Failed: " + result.error();
		channel.setLastTestAt(System.currentTimeMillis());
		channel.setLastTestStatus(outcome);
		channelRepository.save(channel);
		LOG.info("Alert channel {} tested by {}: {}", id, user, outcome);
		return outcome;
	}

	/**
	 * @throws IllegalArgumentException with a user-facing reason if the route is invalid
	 */
	public void addRoute(RouteRequest request, String user) {
		ValidRoute valid = validate(request);
		AlertRouteEntity route = new AlertRouteEntity();
		apply(route, valid, request, user);
		routeRepository.save(route);
		LOG.info("Alert route for {} to channel {} added by {}", request.alertType(),
				request.channelId(), user);
	}

	/**
	 * Replaces every setting of an existing route; its enabled state is kept.
	 *
	 * @throws IllegalArgumentException with a user-facing reason if the route is invalid or
	 *                                  does not exist
	 */
	public void updateRoute(long id, RouteRequest request, String user) {
		ValidRoute valid = validate(request);
		AlertRouteEntity route = routeRepository.findById(id)
				.orElseThrow(() -> new IllegalArgumentException("No such route."));
		apply(route, valid, request, user);
		routeRepository.save(route);
		LOG.info("Alert route {} for {} to channel {} updated by {}", id, request.alertType(),
				request.channelId(), user);
	}

	/**
	 * Checks a route exactly as {@link #addRoute} would, without saving it.
	 *
	 * @throws IllegalArgumentException with a user-facing reason if the route is invalid
	 */
	public void checkRoute(RouteRequest request) {
		validate(request);
	}

	/** A route request that passed validation, with its filters normalised. */
	private record ValidRoute(AlertChannelEntity channel, String apiLabelFilter,
			String repoInclude, String repoExclude) {
	}

	private ValidRoute validate(RouteRequest request) {
		if (registry.get(request.alertType()).isEmpty()) {
			throw new IllegalArgumentException("Choose a known alert type.");
		}
		if (request.aggregation() == null) {
			throw new IllegalArgumentException("Choose how alerts are grouped.");
		}
		if (request.dedupeWindowHours() < 1
				|| request.dedupeWindowHours() > MAX_DEDUPE_WINDOW_HOURS) {
			throw new IllegalArgumentException("The dedupe window must be between 1 and "
					+ MAX_DEDUPE_WINDOW_HOURS + " hours.");
		}
		String apiLabelFilter = validFilter(request.apiLabelFilter(), API_LABEL, "SCM label");
		String repoInclude = validFilter(request.repoInclude(), GLOB_LIST, "Include");
		String repoExclude = validFilter(request.repoExclude(), GLOB_LIST, "Exclude");
		AlertChannelEntity channel = channelRepository.findById(request.channelId())
				.orElseThrow(() -> new IllegalArgumentException("Choose an existing channel."));
		return new ValidRoute(channel, apiLabelFilter, repoInclude, repoExclude);
	}

	private static void apply(AlertRouteEntity route, ValidRoute valid, RouteRequest request,
			String user) {
		route.setAlertType(request.alertType());
		route.setChannel(valid.channel());
		route.setMinPriority(request.minPriority());
		route.setApiLabelFilter(valid.apiLabelFilter());
		route.setRepoInclude(valid.repoInclude());
		route.setRepoExclude(valid.repoExclude());
		route.setAggregation(request.aggregation());
		route.setDedupeWindowHours(request.dedupeWindowHours());
		route.setUpdatedBy(user);
		route.setUpdatedAt(System.currentTimeMillis());
	}

	public void setRouteEnabled(long id, boolean enabled, String user) {
		AlertRouteEntity route = routeRepository.findById(id)
				.orElseThrow(() -> new IllegalArgumentException("No such route."));
		route.setEnabled(enabled);
		route.setUpdatedBy(user);
		route.setUpdatedAt(System.currentTimeMillis());
		routeRepository.save(route);
		LOG.info("Alert route {} {} by {}", id, enabled ? "enabled" : "disabled", user);
	}

	public void deleteRoute(long id, String user) {
		AlertRouteEntity route = routeRepository.findById(id)
				.orElseThrow(() -> new IllegalArgumentException("No such route."));
		routeRepository.delete(route);
		LOG.info("Alert route {} deleted by {}", id, user);
	}

	/**
	 * The encrypting converter stores plaintext when encryption is off; a webhook URL is a
	 * credential, so production refuses rather than store it that way.
	 */
	/** Whether saved webhook URLs are encrypted at rest, so the page states what really happens. */
	public boolean isCredentialEncryptionActive() {
		return encryptionType != EncryptionType.NONE;
	}

	private void requireEncryptedStorage() {
		if (production && encryptionType == EncryptionType.NONE) {
			throw new IllegalArgumentException("Database encryption is not configured"
					+ " (watchtower.encryption.type=none), so the webhook URL would be stored in"
					+ " plaintext. Configure encryption before adding alert channels.");
		}
	}

	private AlertChannelEntity channel(long id) {
		return channelRepository.findById(id)
				.orElseThrow(() -> new IllegalArgumentException("No such channel."));
	}

	private static String validName(String raw) {
		String name = StringUtils.trimToNull(raw);
		if (name == null || name.length() > MAX_NAME_LENGTH || !NAME.matcher(name).matches()) {
			throw new IllegalArgumentException("A channel name of up to " + MAX_NAME_LENGTH
					+ " letters, digits, spaces, '.', '_' or '-' is required.");
		}
		return name;
	}

	private static String validFilter(String raw, Pattern allowed, String field) {
		String value = StringUtils.trimToNull(raw);
		if (value == null) {
			return null;
		}
		if (value.length() > MAX_FILTER_LENGTH || !allowed.matcher(value).matches()) {
			throw new IllegalArgumentException(field + " may only use letters, digits, '.', '_',"
					+ " '-', '*' and commas.");
		}
		return value;
	}
}
