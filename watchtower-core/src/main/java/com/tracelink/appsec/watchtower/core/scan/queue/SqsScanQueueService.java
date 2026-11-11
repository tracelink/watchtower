package com.tracelink.appsec.watchtower.core.scan.queue;

import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.ChangeMessageVisibilityRequest;
import software.amazon.awssdk.services.sqs.model.DeleteMessageRequest;
import software.amazon.awssdk.services.sqs.model.Message;
import software.amazon.awssdk.services.sqs.model.ReceiveMessageRequest;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;

/**
 * Wraps the SQS FIFO scan queue used by the pull-request submission and consumer paths.
 * <p>
 * Operates in no-op mode when {@code watchtower.queue.sqs.queue-url} is blank, the same
 * pattern as {@link com.tracelink.appsec.watchtower.core.scan.storage.S3Service}.
 *
 * @author Watchtower
 */
@Service
public class SqsScanQueueService {
	private static final Logger LOG = LoggerFactory.getLogger(SqsScanQueueService.class);

	private final String queueUrl;
	private final int pollWaitSeconds;
	private final int maxMessagesPerPoll;
	private final ObjectMapper objectMapper;
	private final SqsClient sqsClient;
	private final PRScanWorkloadService workloadService;

	@Autowired
	public SqsScanQueueService(@Value("${watchtower.queue.sqs.queue-url:}") String queueUrl,
			@Value("${watchtower.queue.sqs.region:us-east-1}") String region,
			@Value("${watchtower.queue.sqs.poll-wait-seconds:20}") int pollWaitSeconds,
			@Value("${watchtower.queue.sqs.max-messages-per-poll:4}") int maxMessagesPerPoll,
			PRScanWorkloadService workloadService) {
		this.queueUrl = queueUrl;
		this.pollWaitSeconds = pollWaitSeconds;
		this.maxMessagesPerPoll = maxMessagesPerPoll;
		this.workloadService = workloadService;
		// A plain ObjectMapper, not an injected Spring bean: ScanRequestMessage is a
		// simple 5-field record with no custom serializers or date/time types that would
		// need any special Jackson module configuration, so there's nothing to gain from
		// sharing the app's ObjectMapper bean - and watchtower-core's own minimal test
		// context (WatchtowerTestApplication) has no Jackson autoconfiguration on its
		// classpath to provide one.
		this.objectMapper = new ObjectMapper();
		this.sqsClient = queueUrl.isBlank() ? null
				: SqsClient.builder().region(Region.of(region))
						.credentialsProvider(DefaultCredentialsProvider.create()).build();
	}

	/**
	 * Test-only seam: lets {@code SqsScanQueueServiceTest} inject a mocked
	 * {@link SqsClient} directly, since the public constructor's real client can't be
	 * exercised against a real AWS endpoint in a unit test.
	 *
	 * @param queueUrl  the queue URL to operate against
	 * @param sqsClient the client to use, or null for no-op mode
	 */
	SqsScanQueueService(String queueUrl, SqsClient sqsClient) {
		this.queueUrl = queueUrl;
		this.pollWaitSeconds = 20;
		this.maxMessagesPerPoll = 4;
		this.objectMapper = new ObjectMapper();
		this.sqsClient = sqsClient;
		this.workloadService = null;
	}

	/**
	 * @return true if a queue URL is configured and this service will actually talk to
	 *         SQS
	 */
	public boolean isEnabled() {
		return sqsClient != null;
	}

	/**
	 * @return whether a scan of the pull request is queued or running on any pod; false when
	 *         the queue is off, since each pod then tracks only its own scans
	 */
	public boolean hasPendingScan(String apiLabel, String repoName, String prId) {
		return workloadService != null
				&& workloadService.hasPendingScan(apiLabel, repoName, prId);
	}

	/**
	 * Publishes a scan request to the FIFO queue. The message group is scoped per
	 * repository ({@code apiLabel/repoName}), not one fixed group for the whole queue,
	 * so a future consumer (item 4.5) can process different repositories concurrently
	 * while still getting strict in-order delivery for scans of the same repository.
	 * The deduplication id matches {@code PRScanningService}'s own in-memory dedup key
	 * shape (apiLabel/repoName/prId/commitHash), so a retried webhook delivery for the
	 * same commit is deduplicated by SQS itself once this is wired into the submission
	 * path, not just by this one pod's in-memory map. If ingress does not know the commit
	 * yet, the submission timestamp keeps separate manual requests from collapsing into
	 * the same FIFO deduplication window.
	 * <p>
	 * A serialization or publish failure is logged and returned to the caller so the UI
	 * does not report a scan as queued when SQS rejected it.
	 *
	 * @param message the scan request to publish
	 */
	public boolean publish(ScanRequestMessage message) {
		if (sqsClient == null) {
			return false;
		}
		String groupId = message.apiLabel() + "/" + message.repoName();
		try {
			String body = objectMapper.writeValueAsString(message);
			String messageVersion = message.commitHash() == null
					|| message.commitHash().isBlank()
						? Long.toString(message.enqueuedAt()) : message.commitHash();
			String dedupId = groupId + "/" + message.prId() + "/" + messageVersion;
			sqsClient.sendMessage(SendMessageRequest.builder().queueUrl(queueUrl).messageBody(body)
					.messageGroupId(groupId).messageDeduplicationId(dedupId).build());
			track("queue", () -> workloadService.queued(message));
			return true;
		} catch (JsonProcessingException e) {
			LOG.error("Failed to serialize scan request for " + groupId + "/" + message.prId(), e);
		} catch (SdkException e) {
			LOG.error("Failed to publish scan request for " + groupId + "/" + message.prId()
					+ " to SQS", e);
		}
		return false;
	}

	public void markRunning(ScanRequestMessage message) {
		track("mark running", () -> workloadService.running(message));
	}

	public void markQueued(ScanRequestMessage message) {
		track("mark queued", () -> workloadService.queued(message));
	}

	public void markCompleted(ScanRequestMessage message) {
		track("complete", () -> workloadService.completed(message));
	}

	public void markValidationFailed(ScanRequestMessage message, String reason) {
		track("record validation failure", () -> workloadService.validationFailed(message, reason));
	}

	private void track(String action, Runnable operation) {
		if (workloadService == null) return;
		try {
			operation.run();
		} catch (RuntimeException e) {
			// Observability must never prevent SQS delivery or scan execution. A later
			// consumer transition can recreate a missing work item.
			LOG.error("Could not " + action + " PR scan workload entry", e);
		}
	}

	/**
	 * Polls for up to {@code watchtower.queue.sqs.max-messages-per-poll} messages,
	 * long-polling for {@code watchtower.queue.sqs.poll-wait-seconds}.
	 *
	 * @return the messages received, or an empty list if none arrived, SQS is
	 *         unreachable, or no queue is configured
	 */
	public List<Message> poll() {
		if (sqsClient == null) {
			return Collections.emptyList();
		}
		try {
			return sqsClient.receiveMessage(ReceiveMessageRequest.builder().queueUrl(queueUrl)
					.waitTimeSeconds(pollWaitSeconds).maxNumberOfMessages(maxMessagesPerPoll)
					.build()).messages();
		} catch (SdkException e) {
			LOG.error("Failed to poll SQS queue " + queueUrl, e);
			return Collections.emptyList();
		}
	}

	/**
	 * Deletes a message after it has been fully processed.
	 *
	 * @param receiptHandle the receipt handle from the {@link Message} that was polled
	 */
	public void delete(String receiptHandle) {
		if (sqsClient == null) {
			return;
		}
		try {
			sqsClient.deleteMessage(
					DeleteMessageRequest.builder().queueUrl(queueUrl).receiptHandle(receiptHandle)
							.build());
		} catch (SdkException e) {
			LOG.error("Failed to delete SQS message on queue " + queueUrl, e);
		}
	}

	/**
	 * Delays redelivery of a message (item 4.7's rate-limit retry) by changing its
	 * visibility timeout, rather than deleting and re-publishing it - a fresh publish
	 * would mint a new {@code MessageDeduplicationId} and could reorder it relative to
	 * other messages in the same FIFO group.
	 * <p>
	 * Returns whether the change actually took effect, unlike this class's other
	 * best-effort methods: item 4.7's caller needs to know a failed requeue so it can
	 * fall back (the message's original visibility timeout will still redeliver it
	 * eventually, just later and without the caller's chosen delay).
	 *
	 * @param receiptHandle the receipt handle from the {@link Message} that was polled
	 * @param delaySeconds  how long before the message becomes visible again
	 * @return true if the visibility timeout was changed; false if no queue is
	 *         configured or the request to SQS failed
	 */
	public boolean requeue(String receiptHandle, int delaySeconds) {
		if (sqsClient == null) {
			return false;
		}
		try {
			sqsClient.changeMessageVisibility(
					ChangeMessageVisibilityRequest.builder().queueUrl(queueUrl)
							.receiptHandle(receiptHandle).visibilityTimeout(delaySeconds).build());
			return true;
		} catch (SdkException e) {
			LOG.error("Failed to change visibility timeout for a message on queue " + queueUrl, e);
			return false;
		}
	}
}
