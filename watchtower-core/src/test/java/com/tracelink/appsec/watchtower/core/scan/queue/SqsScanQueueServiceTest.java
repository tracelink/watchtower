package com.tracelink.appsec.watchtower.core.scan.queue;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.ChangeMessageVisibilityRequest;
import software.amazon.awssdk.services.sqs.model.DeleteMessageRequest;
import software.amazon.awssdk.services.sqs.model.Message;
import software.amazon.awssdk.services.sqs.model.QueueDoesNotExistException;
import software.amazon.awssdk.services.sqs.model.ReceiveMessageRequest;
import software.amazon.awssdk.services.sqs.model.ReceiveMessageResponse;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;

/**
 * IMPROVEMENT_PLAN.md item 4.3's test requirements: no-op mode when unconfigured, and
 * mocked {@link SqsClient} behavior for publish/poll when configured.
 */
public class SqsScanQueueServiceTest {

	private ScanRequestMessage sampleMessage() {
		return new ScanRequestMessage("api1", "my-repo", "7", "abc123", 1700000000000L);
	}

	@Test
	public void testNoOpModeWhenQueueUrlBlank() {
		SqsScanQueueService service = new SqsScanQueueService("", null);

		assertFalse(service.isEnabled());
		assertTrue(service.poll().isEmpty());
		// publish/delete/requeue are no-ops; the assertion is that none of them throw
		// with no SqsClient ever constructed.
		assertFalse(service.publish(sampleMessage()));
		service.delete("some-receipt-handle");
		service.requeue("some-receipt-handle", 30);
	}

	@Test
	public void testIsEnabledWhenQueueUrlConfigured() {
		SqsScanQueueService service =
				new SqsScanQueueService("https://sqs.us-east-1.amazonaws.com/123/queue.fifo",
						mock(SqsClient.class));

		assertTrue(service.isEnabled());
	}

	@Test
	public void testPublishSendsMessageWithGroupAndDedupId() {
		SqsClient mockClient = mock(SqsClient.class);
		SqsScanQueueService service = new SqsScanQueueService("queue-url", mockClient);

		assertTrue(service.publish(sampleMessage()));

		org.mockito.ArgumentCaptor<SendMessageRequest> captor =
				org.mockito.ArgumentCaptor.forClass(SendMessageRequest.class);
		verify(mockClient).sendMessage(captor.capture());
		SendMessageRequest sent = captor.getValue();
		assertEquals("api1/my-repo", sent.messageGroupId());
		assertEquals("api1/my-repo/7/abc123", sent.messageDeduplicationId());
		assertTrue(sent.messageBody().contains("abc123"));
	}

	@Test
	public void testPublishUsesSubmissionTimeWhenCommitIsNotKnownYet() {
		SqsClient mockClient = mock(SqsClient.class);
		SqsScanQueueService service = new SqsScanQueueService("queue-url", mockClient);
		ScanRequestMessage message = new ScanRequestMessage("api1", "my-repo", "7", null,
				1700000000000L);

		assertTrue(service.publish(message));

		org.mockito.ArgumentCaptor<SendMessageRequest> captor =
				org.mockito.ArgumentCaptor.forClass(SendMessageRequest.class);
		verify(mockClient).sendMessage(captor.capture());
		assertEquals("api1/my-repo/7/1700000000000",
				captor.getValue().messageDeduplicationId());
	}

	@Test
	public void testPublishSwallowsSdkFailure() {
		SqsClient mockClient = mock(SqsClient.class);
		given(mockClient.sendMessage(any(SendMessageRequest.class)))
				.willThrow(QueueDoesNotExistException.builder().message("boom").build());
		SqsScanQueueService service = new SqsScanQueueService("queue-url", mockClient);

		assertFalse(service.publish(sampleMessage()));
	}

	@Test
	public void testPollReturnsMessagesFromReceiveMessage() {
		SqsClient mockClient = mock(SqsClient.class);
		Message message = Message.builder().body("body").receiptHandle("handle").build();
		given(mockClient.receiveMessage(any(ReceiveMessageRequest.class)))
				.willReturn(ReceiveMessageResponse.builder().messages(message).build());
		SqsScanQueueService service = new SqsScanQueueService("queue-url", mockClient);

		List<Message> messages = service.poll();

		assertEquals(1, messages.size());
		assertEquals("handle", messages.get(0).receiptHandle());
	}

	@Test
	public void testPollReturnsEmptyListOnSdkFailure() {
		SqsClient mockClient = mock(SqsClient.class);
		given(mockClient.receiveMessage(any(ReceiveMessageRequest.class)))
				.willThrow(QueueDoesNotExistException.builder().message("boom").build());
		SqsScanQueueService service = new SqsScanQueueService("queue-url", mockClient);

		assertEquals(Collections.emptyList(), service.poll());
	}

	@Test
	public void testDeleteCallsDeleteMessage() {
		SqsClient mockClient = mock(SqsClient.class);
		SqsScanQueueService service = new SqsScanQueueService("queue-url", mockClient);

		service.delete("handle");

		verify(mockClient).deleteMessage(any(DeleteMessageRequest.class));
	}

	@Test
	public void testRequeueChangesVisibilityTimeout() {
		SqsClient mockClient = mock(SqsClient.class);
		SqsScanQueueService service = new SqsScanQueueService("queue-url", mockClient);

		service.requeue("handle", 45);

		org.mockito.ArgumentCaptor<ChangeMessageVisibilityRequest> captor =
				org.mockito.ArgumentCaptor.forClass(ChangeMessageVisibilityRequest.class);
		verify(mockClient).changeMessageVisibility(captor.capture());
		assertEquals(45, captor.getValue().visibilityTimeout());
	}
}
