package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.queue;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.BDDMockito;

import com.tracelink.appsec.watchtower.core.queue.SqsQueueClient;

import software.amazon.awssdk.services.sqs.model.Message;

public class RepoQueueConsumerTest {

	private SqsQueueClient client;

	private RepoWorkProcessor processor;

	private RepoQueueConsumer consumer;

	@BeforeEach
	public void setup() {
		client = BDDMockito.mock(SqsQueueClient.class);
		processor = BDDMockito.mock(RepoWorkProcessor.class);
		consumer = new RepoQueueConsumer(client, processor, 300);
	}

	private static Message message(String body) {
		return Message.builder().body(body).receiptHandle("rh").build();
	}

	@Test
	public void deletesFinishedWorkAndDelaysRetries() {
		BDDMockito.when(processor.canStartScan()).thenReturn(true);
		BDDMockito.when(processor.process(ArgumentMatchers.any(), ArgumentMatchers.any()))
				.thenReturn(WorkOutcome.done());
		consumer.handle(message(RepoQueueMessage.scan(1).toJson()));
		BDDMockito.verify(client).delete("rh");

		BDDMockito.when(processor.process(ArgumentMatchers.any(), ArgumentMatchers.any()))
				.thenReturn(WorkOutcome.retryLater(45));
		consumer.handle(message(RepoQueueMessage.job(2).toJson()));
		BDDMockito.verify(client).changeVisibility("rh", 45);
	}

	@Test
	public void releasesAScanWhileThisPodIsBusyWithPullRequests() {
		BDDMockito.when(processor.canStartScan()).thenReturn(false);

		consumer.handle(message(RepoQueueMessage.scan(1).toJson()));

		BDDMockito.verify(client).changeVisibility("rh", RepoQueueConsumer.RELEASE_SECONDS);
		BDDMockito.verify(processor, BDDMockito.never()).process(ArgumentMatchers.any(),
				ArgumentMatchers.any());
	}

	@Test
	public void dropsUnreadableMessages() {
		consumer.handle(message("garbage"));
		BDDMockito.verify(client).delete("rh");
	}

	@Test
	public void doesNothingWithoutAQueueOrWhilePaused() {
		consumer.poll();
		BDDMockito.when(client.isEnabled()).thenReturn(true);
		BDDMockito.when(processor.isPaused()).thenReturn(true);
		consumer.poll();
		BDDMockito.verify(client, BDDMockito.never()).receive(ArgumentMatchers.anyInt(),
				ArgumentMatchers.anyInt());
	}

	@Test
	public void sqsQueuePutsEveryScanInOneGroup() {
		SqsRepoWorkQueue sqs = new SqsRepoWorkQueue(client);
		sqs.sendScan(9);
		sqs.sendJob(3, "job-3");
		BDDMockito.verify(client).send(RepoQueueMessage.scan(9).toJson(), "scan", "scan-9");
		BDDMockito.verify(client).send(RepoQueueMessage.job(3).toJson(), "job-3", "job-3");
		Assertions.assertTrue(sqs.isDistributed());
	}
}
