package com.tracelink.appsec.watchtower.core.alerting;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

public class GoogleChatSenderTest {

	private HttpServer server;

	private final AtomicReference<String> body = new AtomicReference<>();

	private final AtomicReference<String> query = new AtomicReference<>();

	private volatile int status = 200;

	private volatile String location;

	/** The real sender only accepts chat.googleapis.com; tests talk to localhost instead. */
	private final UnaryOperator<String> anyUrl = url -> url;

	private GoogleChatSender sender;

	private String url;

	@BeforeEach
	public void setup() throws IOException {
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		server.createContext("/v1/spaces/AAAA/messages", this::handle);
		server.start();
		url = "http://127.0.0.1:" + server.getAddress().getPort()
				+ "/v1/spaces/AAAA/messages?key=k&token=t";
		sender = new GoogleChatSender(GoogleChatSender.defaultClient(), anyUrl);
	}

	@AfterEach
	public void teardown() {
		server.stop(0);
	}

	private void handle(HttpExchange exchange) throws IOException {
		body.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
		query.set(exchange.getRequestURI().getRawQuery());
		if (location != null) {
			exchange.getResponseHeaders().add("Location", location);
		}
		byte[] response = "{}".getBytes(StandardCharsets.UTF_8);
		exchange.sendResponseHeaders(status, response.length);
		try (OutputStream out = exchange.getResponseBody()) {
			out.write(response);
		}
	}

	@Test
	public void testPostsTheTextAsJsonInTheThread() {
		GoogleChatSender.SendResult result = sender.send(url, "Secret \"detected\"", "pr-42");

		Assertions.assertTrue(result.success(), String.valueOf(result.error()));
		Assertions.assertEquals("{\"text\":\"Secret \\\"detected\\\"\"}", body.get());
		MatcherAssert.assertThat(query.get(), Matchers.allOf(
				Matchers.containsString("key=k&token=t"),
				Matchers.containsString("threadKey="),
				Matchers.containsString("messageReplyOption=REPLY_MESSAGE_FALLBACK_TO_NEW_THREAD")));
		MatcherAssert.assertThat(query.get(), Matchers.not(Matchers.containsString("pr-42")));
	}

	@Test
	public void testNoThreadKeyMeansANewMessage() {
		sender.send(url, "hello", null);

		Assertions.assertEquals("key=k&token=t", query.get());
	}

	@Test
	public void testErrorResponseIsAFailureThatNeverIncludesTheUrl() {
		status = 403;

		GoogleChatSender.SendResult result = sender.send(url, "hello", null);

		Assertions.assertFalse(result.success());
		Assertions.assertEquals("HTTP 403", result.error());
	}

	@Test
	public void testRedirectsAreNotFollowed() {
		status = 302;
		location = "http://169.254.169.254/latest/meta-data/";

		GoogleChatSender.SendResult result = sender.send(url, "hello", null);

		Assertions.assertFalse(result.success());
		Assertions.assertEquals("HTTP 302", result.error());
	}

	@Test
	public void testUnreachableChannelIsAFailureWithoutTheUrl() {
		server.stop(0);

		GoogleChatSender.SendResult result = sender.send(url, "hello", null);

		Assertions.assertFalse(result.success());
		MatcherAssert.assertThat(result.error(), Matchers.not(Matchers.containsString("token")));
	}

	@Test
	public void testTheDefaultSenderRefusesAnythingButGoogleChat() {
		GoogleChatSender strict = new GoogleChatSender();

		GoogleChatSender.SendResult result = strict.send(url, "hello", null);

		Assertions.assertFalse(result.success());
		Assertions.assertNull(body.get(), "nothing may be sent to a non-Chat host");
	}

	@Test
	public void testDefaultClientNeverFollowsRedirects() {
		Assertions.assertEquals(HttpClient.Redirect.NEVER,
				GoogleChatSender.defaultClient().followRedirects());
	}
}
