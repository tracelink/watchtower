package com.tracelink.appsec.watchtower.core.alerting;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.BDDMockito;

import com.tracelink.appsec.watchtower.core.alerting.entity.AlertChannelEntity;
import com.tracelink.appsec.watchtower.core.alerting.entity.AlertLogEntity;
import com.tracelink.appsec.watchtower.core.alerting.repository.AlertChannelRepository;
import com.tracelink.appsec.watchtower.core.alerting.repository.AlertLogRepository;

public class AlertDeliveryWorkerTest {

	private static final Instant NOW = Instant.parse("2026-09-25T12:00:00Z");

	private AlertLogRepository logRepository;

	private AlertChannelRepository channelRepository;

	private GoogleChatSender sender;

	private AlertDeliveryWorker worker;

	private AlertChannelEntity channel;

	@BeforeEach
	public void setup() {
		logRepository = BDDMockito.mock(AlertLogRepository.class);
		channelRepository = BDDMockito.mock(AlertChannelRepository.class);
		sender = BDDMockito.mock(GoogleChatSender.class);
		worker = new AlertDeliveryWorker(logRepository, channelRepository, sender,
				Clock.fixed(NOW, ZoneOffset.UTC), millis -> {
				}, null);
		channel = new AlertChannelEntity();
		channel.setName("appsec");
		channel.setWebhookUrl("https://chat.googleapis.com/v1/spaces/AAAA/messages?key=k");
		BDDMockito.when(channelRepository.findById(BDDMockito.anyLong()))
				.thenReturn(Optional.of(channel));
		BDDMockito.when(logRepository.claim(BDDMockito.anyLong(), BDDMockito.anyLong(),
				BDDMockito.anyLong(), BDDMockito.any())).thenReturn(1);
	}

	@Test
	public void testAMessageAnotherInstanceClaimedIsNotSentTwice() {
		AlertLogEntity message = new AlertLogEntity();
		message.setChannelId(1L);
		message.setStatus(AlertStatus.PENDING);
		message.setNextAttemptAt(NOW.toEpochMilli() - 10);
		BDDMockito.when(logRepository.findTop20ByStatusAndNextAttemptAtLessThanEqualOrderByIdAsc(
				AlertStatus.PENDING, NOW.toEpochMilli())).thenReturn(List.of(message));
		BDDMockito.when(logRepository.claim(message.getId(), NOW.toEpochMilli() - 10,
				NOW.toEpochMilli() + AlertDeliveryWorker.LEASE_MS, AlertStatus.PENDING))
				.thenReturn(0);

		worker.deliverDue();

		BDDMockito.verifyNoInteractions(sender);
		BDDMockito.verify(logRepository, BDDMockito.never()).save(BDDMockito.any());
	}

	private AlertLogEntity due(int attempts) {
		AlertLogEntity message = new AlertLogEntity();
		message.setAttempts(attempts);
		message.setPayload("*Secrets detected*");
		message.setThreadKey("pr-42");
		BDDMockito.when(logRepository.findTop20ByStatusAndNextAttemptAtLessThanEqualOrderByIdAsc(
				AlertStatus.PENDING, NOW.toEpochMilli())).thenReturn(List.of(message));
		return message;
	}

	@Test
	public void testSentMessageIsMarkedSent() {
		AlertLogEntity message = due(0);
		BDDMockito.when(sender.send(channel.getWebhookUrl(), "*Secrets detected*", "pr-42"))
				.thenReturn(GoogleChatSender.SendResult.ok());

		worker.deliverDue();

		Assertions.assertEquals(AlertStatus.SENT, message.getStatus());
		Assertions.assertEquals(NOW.toEpochMilli(), message.getSentAt());
		BDDMockito.verify(logRepository).save(message);
	}

	@Test
	public void testFailedMessageIsRetriedWithBackoff() {
		AlertLogEntity message = due(0);
		BDDMockito.when(sender.send(BDDMockito.any(), BDDMockito.any(), BDDMockito.any()))
				.thenReturn(GoogleChatSender.SendResult.failed("HTTP 503"));

		worker.deliverDue();

		Assertions.assertEquals(AlertStatus.PENDING, message.getStatus());
		Assertions.assertEquals(1, message.getAttempts());
		Assertions.assertEquals(NOW.toEpochMilli() + AlertDeliveryWorker.BACKOFF_MS[0],
				message.getNextAttemptAt());
		Assertions.assertEquals("HTTP 503", message.getLastError());
	}

	@Test
	public void testThirdFailureIsFinal() {
		AlertLogEntity message = due(AlertDeliveryWorker.MAX_ATTEMPTS - 1);
		BDDMockito.when(sender.send(BDDMockito.any(), BDDMockito.any(), BDDMockito.any()))
				.thenReturn(GoogleChatSender.SendResult.failed("timeout"));

		worker.deliverDue();

		Assertions.assertEquals(AlertStatus.FAILED, message.getStatus());
		Assertions.assertEquals(AlertDeliveryWorker.MAX_ATTEMPTS, message.getAttempts());
	}

	@Test
	public void testDisabledOrDeletedChannelFailsTheMessageWithoutSending() {
		AlertLogEntity message = due(0);
		channel.setEnabled(false);

		worker.deliverDue();

		Assertions.assertEquals(AlertStatus.FAILED, message.getStatus());
		BDDMockito.verifyNoInteractions(sender);
	}

	@Test
	public void testSendsToTheSameChannelAreSpacedOut() {
		AlertLogEntity first = new AlertLogEntity();
		first.setPayload("one");
		AlertLogEntity second = new AlertLogEntity();
		second.setPayload("two");
		BDDMockito.when(logRepository.findTop20ByStatusAndNextAttemptAtLessThanEqualOrderByIdAsc(
				AlertStatus.PENDING, NOW.toEpochMilli())).thenReturn(List.of(first, second));
		BDDMockito.when(sender.send(BDDMockito.any(), BDDMockito.any(), BDDMockito.any()))
				.thenReturn(GoogleChatSender.SendResult.ok());
		List<Long> sleeps = new java.util.ArrayList<>();
		worker = new AlertDeliveryWorker(logRepository, channelRepository, sender,
				Clock.fixed(NOW, ZoneOffset.UTC), sleeps::add, null);

		worker.deliverDue();

		Assertions.assertEquals(List.of(AlertDeliveryWorker.MIN_CHANNEL_INTERVAL_MS), sleeps);
	}

	@Test
	public void testAWorkerErrorNeverEscapes() {
		BDDMockito.when(logRepository.findTop20ByStatusAndNextAttemptAtLessThanEqualOrderByIdAsc(
				BDDMockito.any(), BDDMockito.anyLong()))
				.thenThrow(new IllegalStateException("database down"));

		worker.deliverDue();
	}
}
