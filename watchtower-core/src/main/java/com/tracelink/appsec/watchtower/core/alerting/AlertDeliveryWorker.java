package com.tracelink.appsec.watchtower.core.alerting;

import java.time.Clock;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongConsumer;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.tracelink.appsec.watchtower.core.alerting.entity.AlertChannelEntity;
import com.tracelink.appsec.watchtower.core.alerting.entity.AlertLogEntity;
import com.tracelink.appsec.watchtower.core.alerting.repository.AlertChannelRepository;
import com.tracelink.appsec.watchtower.core.alerting.repository.AlertLogRepository;

import io.micrometer.core.instrument.MeterRegistry;

/**
 * Sends queued alert messages. Each message gets {@link #MAX_ATTEMPTS} tries with backoff, and
 * sends to one channel are spaced at least {@link #MIN_CHANNEL_INTERVAL_MS} apart to respect
 * Google Chat's per-space rate limit.
 *
 * @author Watchtower
 */
@Component
public class AlertDeliveryWorker {

	private static final Logger LOG = LoggerFactory.getLogger(AlertDeliveryWorker.class);

	static final int MAX_ATTEMPTS = 3;

	/** Wait before the second and third attempts. */
	static final long[] BACKOFF_MS = {60_000L, 300_000L};

	static final long MIN_CHANNEL_INTERVAL_MS = 1_000L;

	/**
	 * How long a claimed message is held by one instance: well over a send's connect and read
	 * timeouts plus the per-channel spacing, so a slow send is never taken over and sent twice.
	 */
	static final long LEASE_MS = 120_000L;

	private static final int MAX_ERROR_LENGTH = 500;

	private final AlertLogRepository logRepository;

	private final AlertChannelRepository channelRepository;

	private final GoogleChatSender sender;

	private final Clock clock;

	private final LongConsumer sleeper;

	private final MeterRegistry meterRegistry;

	@Autowired
	public AlertDeliveryWorker(AlertLogRepository logRepository,
			AlertChannelRepository channelRepository, GoogleChatSender sender,
			ObjectProvider<MeterRegistry> meterRegistry) {
		this(logRepository, channelRepository, sender, Clock.systemUTC(),
				AlertDeliveryWorker::sleep, meterRegistry.getIfAvailable());
	}

	AlertDeliveryWorker(AlertLogRepository logRepository, AlertChannelRepository channelRepository,
			GoogleChatSender sender, Clock clock, LongConsumer sleeper,
			MeterRegistry meterRegistry) {
		this.logRepository = logRepository;
		this.channelRepository = channelRepository;
		this.sender = sender;
		this.clock = clock;
		this.sleeper = sleeper;
		this.meterRegistry = meterRegistry;
	}

	/**
	 * Sends every message that is due.
	 */
	@Scheduled(initialDelayString = "${watchtower.alerts.delivery-initial-delay-ms:30000}",
			fixedDelayString = "${watchtower.alerts.delivery-delay-ms:5000}")
	public void deliverDue() {
		try {
			List<AlertLogEntity> due = logRepository
					.findTop20ByStatusAndNextAttemptAtLessThanEqualOrderByIdAsc(
							AlertStatus.PENDING, clock.millis());
			Map<Long, Long> lastSendByChannel = new HashMap<>();
			for (AlertLogEntity message : due) {
				deliver(message, lastSendByChannel);
			}
		} catch (RuntimeException e) {
			LOG.error("Alert delivery pass failed", e);
		}
	}

	private void deliver(AlertLogEntity message, Map<Long, Long> lastSendByChannel) {
		// Claimed per message, just before sending, so the lease only has to cover one send.
		long leaseUntil = clock.millis() + LEASE_MS;
		if (logRepository.claim(message.getId(), message.getNextAttemptAt(), leaseUntil,
				AlertStatus.PENDING) != 1) {
			return;
		}
		message.setNextAttemptAt(leaseUntil);
		AlertChannelEntity channel =
				channelRepository.findById(message.getChannelId()).orElse(null);
		if (channel == null || !channel.isEnabled()) {
			message.setStatus(AlertStatus.FAILED);
			message.setLastError("channel deleted or disabled");
			logRepository.save(message);
			count("failed");
			return;
		}
		if (lastSendByChannel.containsKey(message.getChannelId())) {
			sleeper.accept(MIN_CHANNEL_INTERVAL_MS);
		}
		GoogleChatSender.SendResult result =
				sender.send(channel.getWebhookUrl(), message.getPayload(), message.getThreadKey());
		long now = clock.millis();
		lastSendByChannel.put(message.getChannelId(), now);
		if (result.success()) {
			message.setStatus(AlertStatus.SENT);
			message.setSentAt(now);
			message.setLastError(null);
			count("sent");
		} else {
			message.setAttempts(message.getAttempts() + 1);
			message.setLastError(StringUtils.abbreviate(result.error(), MAX_ERROR_LENGTH));
			if (message.getAttempts() >= MAX_ATTEMPTS) {
				message.setStatus(AlertStatus.FAILED);
				LOG.warn("Alert {} to channel '{}' failed permanently: {}", message.getId(),
						channel.getName(), result.error());
				count("failed");
			} else {
				message.setNextAttemptAt(now + BACKOFF_MS[message.getAttempts() - 1]);
			}
		}
		logRepository.save(message);
	}

	private static void sleep(long millis) {
		try {
			Thread.sleep(millis);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}

	private void count(String outcome) {
		if (meterRegistry != null) {
			meterRegistry.counter(AlertService.METRIC, "outcome", outcome).increment();
		}
	}
}
