package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.queue;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;

import jakarta.annotation.PreDestroy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.tracelink.appsec.watchtower.core.queue.SqsQueueClient;

import software.amazon.awssdk.services.sqs.model.Message;

/**
 * Takes repository scan work from the SQS queue on every pod. A pod takes a message only when it
 * has a free slot and scans are not paused; a scan that arrives while this pod is busy with pull
 * requests goes back to the queue for any pod to take. Does nothing when no queue is configured.
 *
 * @author Watchtower
 */
@Component
public class RepoQueueConsumer {

	private static final Logger LOG = LoggerFactory.getLogger(RepoQueueConsumer.class);

	/** One slot is effectively the scan (the queue hands out one at a time), one is jobs. */
	static final int SLOTS = 2;

	static final int RELEASE_SECONDS = 30;

	private static final int WAIT_SECONDS = 10;

	private final SqsQueueClient client;

	private final RepoWorkProcessor processor;

	private final int visibilityExtensionSeconds;

	private final Semaphore slots = new Semaphore(SLOTS);

	private final ExecutorService workers = Executors.newFixedThreadPool(SLOTS, runnable -> {
		Thread thread = new Thread(runnable, "repo-scan-worker");
		thread.setDaemon(true);
		return thread;
	});

	@Autowired
	public RepoQueueConsumer(SqsQueueClient repoScanQueueClient, RepoWorkProcessor processor,
			@Value("${watchtower.reposcan.visibility-extension-seconds:300}")
			int visibilityExtensionSeconds) {
		this.client = repoScanQueueClient;
		this.processor = processor;
		this.visibilityExtensionSeconds = visibilityExtensionSeconds;
	}

	@Scheduled(fixedDelayString = "${watchtower.reposcan.consumer-poll-delay-ms:2000}")
	public void poll() {
		if (!client.isEnabled() || processor.isPaused() || !slots.tryAcquire()) {
			return;
		}
		List<Message> messages;
		try {
			messages = client.receive(1, WAIT_SECONDS);
		} catch (RuntimeException e) {
			slots.release();
			throw e;
		}
		if (messages.isEmpty()) {
			slots.release();
			return;
		}
		Message message = messages.get(0);
		workers.execute(() -> {
			try {
				handle(message);
			} finally {
				slots.release();
			}
		});
	}

	void handle(Message message) {
		String receipt = message.receiptHandle();
		Optional<RepoQueueMessage> parsed = RepoQueueMessage.fromJson(message.body());
		if (parsed.isEmpty()) {
			LOG.warn("Dropping an unreadable repository scan queue message");
			client.delete(receipt);
			return;
		}
		RepoQueueMessage work = parsed.get();
		if (work.kind() == RepoQueueMessage.Kind.SCAN && !processor.canStartScan()) {
			client.changeVisibility(receipt, RELEASE_SECONDS);
			return;
		}
		WorkOutcome outcome = processor.process(work,
				() -> client.changeVisibility(receipt, visibilityExtensionSeconds));
		if (outcome.retry()) {
			client.changeVisibility(receipt, outcome.delaySeconds());
		} else {
			client.delete(receipt);
		}
	}

	@PreDestroy
	void shutdown() {
		workers.shutdownNow();
	}
}
