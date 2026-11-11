package com.tracelink.appsec.watchtower.core.alerting;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.Map;
import java.util.function.UnaryOperator;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Posts a text message to a Google Chat incoming webhook. The URL is re-validated before every
 * send, redirects are never followed, and a failure is described without the URL - it holds the
 * space's key and token.
 *
 * @author Watchtower
 */
@Component
public class GoogleChatSender {

	/** The outcome of one send. */
	public record SendResult(boolean success, String error) {

		static SendResult ok() {
			return new SendResult(true, null);
		}

		static SendResult failed(String error) {
			return new SendResult(false, error);
		}
	}

	private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);

	private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);

	private static final ObjectMapper MAPPER = new ObjectMapper();

	private final HttpClient client;

	private final UnaryOperator<String> urlValidator;

	public GoogleChatSender() {
		this(defaultClient(), GoogleChatWebhook::validate);
	}

	GoogleChatSender(HttpClient client, UnaryOperator<String> urlValidator) {
		this.client = client;
		this.urlValidator = urlValidator;
	}

	/**
	 * @return an HTTP client with short timeouts that never follows redirects
	 */
	static HttpClient defaultClient() {
		return HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT)
				.followRedirects(HttpClient.Redirect.NEVER).build();
	}

	/**
	 * @param webhookUrl the channel's webhook URL
	 * @param text       the message
	 * @param threadKey  groups messages into one thread, or null for a new message
	 * @return whether it was accepted
	 */
	public SendResult send(String webhookUrl, String text, String threadKey) {
		String url;
		try {
			url = urlValidator.apply(webhookUrl);
		} catch (IllegalArgumentException e) {
			return SendResult.failed("invalid webhook URL");
		}
		if (threadKey != null) {
			// Hashed: a thread key is arbitrary text, and Chat only needs it to be stable.
			url += (url.contains("?") ? "&" : "?") + "threadKey=" + AlertHashing.sha256(threadKey)
					+ "&messageReplyOption=REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD";
		}
		try {
			HttpRequest request = HttpRequest.newBuilder(URI.create(url))
					.timeout(REQUEST_TIMEOUT)
					.header("Content-Type", "application/json; charset=UTF-8")
					.POST(HttpRequest.BodyPublishers.ofString(
							MAPPER.writeValueAsString(Map.of("text", text))))
					.build();
			HttpResponse<Void> response =
					client.send(request, HttpResponse.BodyHandlers.discarding());
			int code = response.statusCode();
			return code >= 200 && code < 300 ? SendResult.ok() : SendResult.failed("HTTP " + code);
		} catch (HttpTimeoutException e) {
			return SendResult.failed("timeout");
		} catch (JsonProcessingException e) {
			return SendResult.failed("could not encode the message");
		} catch (IOException e) {
			return SendResult.failed("connection failed (" + e.getClass().getSimpleName() + ")");
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			return SendResult.failed("interrupted");
		}
	}
}
