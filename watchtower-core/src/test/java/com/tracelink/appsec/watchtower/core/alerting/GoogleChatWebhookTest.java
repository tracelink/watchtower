package com.tracelink.appsec.watchtower.core.alerting;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class GoogleChatWebhookTest {

	/**
	 * Synthetic: the shape of a Chat incoming-webhook URL, not a real space or key. Split so no
	 * secrets scanner flags this file.
	 */
	static final String VALID = "https://chat.googleapis.com/v1/spaces/AAAAexample/messages"
			+ "?key=" + "AIza" + "SyExampleKeyExampleKeyExample" + "&token=" + "exampleToken123";

	@Test
	public void testAcceptsAGoogleChatIncomingWebhook() {
		Assertions.assertEquals(VALID, GoogleChatWebhook.validate("  " + VALID + " "));
	}

	@ParameterizedTest
	@ValueSource(strings = {
			"http://chat.googleapis.com/v1/spaces/AAAA/messages?key=k&token=t",
			"https://chat.googleapis.com.evil.example/v1/spaces/AAAA/messages?key=k",
			"https://evil.example/v1/spaces/AAAA/messages?key=k",
			"https://user@chat.googleapis.com/v1/spaces/AAAA/messages?key=k",
			"https://chat.googleapis.com:8443/v1/spaces/AAAA/messages?key=k",
			"https://chat.googleapis.com/v1/users/AAAA/messages?key=k",
			"https://chat.googleapis.com/v1/spaces/AAAA/../../admin?key=k",
			"https://chat.googleapis.com/v1/spaces/AAAA/messages#frag",
			"https://169.254.169.254/v1/spaces/AAAA/messages",
			"file:///etc/passwd",
			"not a url",
			""
	})
	public void testRejectsAnythingElse(String url) {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> GoogleChatWebhook.validate(url));
	}

	@Test
	public void testRejectsNull() {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> GoogleChatWebhook.validate(null));
	}

	@Test
	public void testMaskShowsWhereItPointsButNeverTheCredentials() {
		String masked = GoogleChatWebhook.mask(VALID);

		MatcherAssert.assertThat(masked, Matchers.startsWith(
				"https://chat.googleapis.com/v1/spaces/AAAA"));
		MatcherAssert.assertThat(masked, Matchers.not(Matchers.containsString("SyExample")));
		MatcherAssert.assertThat(masked, Matchers.not(Matchers.containsString("exampleToken")));
		MatcherAssert.assertThat(masked, Matchers.containsString("****"));
	}

	@Test
	public void testMaskOfSomethingUnexpectedRevealsNothing() {
		Assertions.assertEquals("****", GoogleChatWebhook.mask("garbage"));
		Assertions.assertEquals("", GoogleChatWebhook.mask(null));
	}
}
