package com.tracelink.appsec.watchtower.core.queue;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.ChangeMessageVisibilityRequest;
import software.amazon.awssdk.services.sqs.model.DeleteMessageRequest;
import software.amazon.awssdk.services.sqs.model.GetQueueAttributesRequest;
import software.amazon.awssdk.services.sqs.model.Message;
import software.amazon.awssdk.services.sqs.model.QueueAttributeName;
import software.amazon.awssdk.services.sqs.model.ReceiveMessageRequest;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;

/**
 * A thin, failure-tolerant client for one SQS FIFO queue. Every call logs and reports failure
 * instead of throwing, so a queue outage degrades work rather than failing requests. Uses IRSA
 * credentials via {@link DefaultCredentialsProvider}, never static keys. With a blank queue url
 * the client is disabled and every call is a no-op.
 *
 * @author Watchtower
 */
public class SqsQueueClient {

	private static final Logger LOG = LoggerFactory.getLogger(SqsQueueClient.class);

	private final String queueUrl;

	private final SqsClient sqsClient;

	/**
	 * @param queueUrl the FIFO queue url, blank to disable
	 * @param region   the queue's AWS region
	 */
	public SqsQueueClient(String queueUrl, String region) {
		this(queueUrl, StringUtils.isBlank(queueUrl) ? null
				: SqsClient.builder().region(Region.of(region))
						.credentialsProvider(DefaultCredentialsProvider.create()).build());
	}

	/**
	 * Test seam: a client over a given (usually mocked) {@link SqsClient}.
	 *
	 * @param queueUrl  the queue url
	 * @param sqsClient the client, or null to disable
	 */
	public SqsQueueClient(String queueUrl, SqsClient sqsClient) {
		this.queueUrl = queueUrl;
		this.sqsClient = sqsClient;
	}

	public boolean isEnabled() {
		return sqsClient != null;
	}

	/**
	 * @param body    the message body
	 * @param groupId the FIFO message group: messages in one group are delivered one at a time,
	 *                in order
	 * @param dedupId repeats of this id within five minutes are dropped by SQS
	 * @return true if the message was accepted
	 */
	public boolean send(String body, String groupId, String dedupId) {
		if (sqsClient == null) {
			return false;
		}
		try {
			sqsClient.sendMessage(SendMessageRequest.builder().queueUrl(queueUrl)
					.messageBody(body).messageGroupId(groupId).messageDeduplicationId(dedupId)
					.build());
			return true;
		} catch (SdkException e) {
			LOG.error("Failed to send a message to group " + groupId + " on " + queueUrl, e);
			return false;
		}
	}

	/**
	 * @param maxMessages the most messages to take, 1-10
	 * @param waitSeconds how long to long-poll for a message, 0-20
	 * @return the messages received, empty on failure
	 */
	public List<Message> receive(int maxMessages, int waitSeconds) {
		if (sqsClient == null) {
			return Collections.emptyList();
		}
		try {
			return sqsClient.receiveMessage(ReceiveMessageRequest.builder().queueUrl(queueUrl)
					.maxNumberOfMessages(maxMessages).waitTimeSeconds(waitSeconds).build())
					.messages();
		} catch (SdkException e) {
			LOG.error("Failed to receive from " + queueUrl, e);
			return Collections.emptyList();
		}
	}

	public void delete(String receiptHandle) {
		if (sqsClient == null) {
			return;
		}
		try {
			sqsClient.deleteMessage(DeleteMessageRequest.builder().queueUrl(queueUrl)
					.receiptHandle(receiptHandle).build());
		} catch (SdkException e) {
			LOG.error("Failed to delete a message from " + queueUrl, e);
		}
	}

	/**
	 * Hides a received message for {@code seconds} more: extends a running message's lease, or
	 * releases one to be redelivered after a delay.
	 *
	 * @return true if the visibility changed
	 */
	public boolean changeVisibility(String receiptHandle, int seconds) {
		if (sqsClient == null) {
			return false;
		}
		try {
			sqsClient.changeMessageVisibility(ChangeMessageVisibilityRequest.builder()
					.queueUrl(queueUrl).receiptHandle(receiptHandle).visibilityTimeout(seconds)
					.build());
			return true;
		} catch (SdkException e) {
			LOG.error("Failed to change a message's visibility on " + queueUrl, e);
			return false;
		}
	}

	/**
	 * @return SQS's approximate count of waiting plus in-flight messages, or empty if unknown
	 */
	public OptionalLong approximateDepth() {
		if (sqsClient == null) {
			return OptionalLong.empty();
		}
		try {
			Map<QueueAttributeName, String> attributes = sqsClient.getQueueAttributes(
					GetQueueAttributesRequest.builder().queueUrl(queueUrl).attributeNames(
							QueueAttributeName.APPROXIMATE_NUMBER_OF_MESSAGES,
							QueueAttributeName.APPROXIMATE_NUMBER_OF_MESSAGES_NOT_VISIBLE)
							.build())
					.attributes();
			return OptionalLong.of(Long.parseLong(attributes.getOrDefault(
					QueueAttributeName.APPROXIMATE_NUMBER_OF_MESSAGES, "0"))
					+ Long.parseLong(attributes.getOrDefault(
							QueueAttributeName.APPROXIMATE_NUMBER_OF_MESSAGES_NOT_VISIBLE, "0")));
		} catch (SdkException | NumberFormatException e) {
			LOG.warn("Could not read the depth of " + queueUrl, e);
			return OptionalLong.empty();
		}
	}
}
