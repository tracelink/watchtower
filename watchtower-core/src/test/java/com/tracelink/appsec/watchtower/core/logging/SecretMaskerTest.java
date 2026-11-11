package com.tracelink.appsec.watchtower.core.logging;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SecretMaskerTest {

	// Synthetic values, split so that no secrets scanner flags this source file.
	private static final String AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE";
	private static final String GITHUB_PAT = "ghp_" + "Xa9Bc3De5Fg7Hi1Jk3Lm5No7Pq9Rs1Tu3Vw5";
	private static final String GITHUB_FINE = "github_pat_" + "11ABCDEFG0abcdefghij_klmnopqrstuv";
	private static final String GITLAB_PAT = "glpat-" + "abcdefghij1234567890";
	private static final String SLACK = "xoxb-" + "123456789012-abcdefghijkl";
	private static final String JWT = "eyJ" + "hbGciOiJIUzI1NiJ9.eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0."
			+ "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

	@Test
	public void testMasksKnownTokenFormatsButKeepsTheirKind() {
		for (String secret : new String[] {AWS_KEY, GITHUB_PAT, GITHUB_FINE, GITLAB_PAT, SLACK,
				JWT}) {
			String masked = SecretMasker.mask("token=" + secret + " end");

			MatcherAssert.assertThat(masked, Matchers.not(Matchers.containsString(secret)));
			MatcherAssert.assertThat(masked, Matchers.containsString("****"));
			MatcherAssert.assertThat(masked, Matchers.endsWith(" end"));
			// The prefix stays, so a log reader still knows what kind of secret it was.
			MatcherAssert.assertThat(masked, Matchers.containsString(secret.substring(0, 4)));
		}
	}

	@Test
	public void testMasksAPrivateKeyBlock() {
		String pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1234\nabcd\n"
				+ "-----END RSA PRIVATE KEY-----";

		String masked = SecretMasker.mask("key: " + pem + " done");

		MatcherAssert.assertThat(masked, Matchers.not(Matchers.containsString("MIIEpAIB")));
		MatcherAssert.assertThat(masked, Matchers.containsString("PRIVATE KEY"));
		MatcherAssert.assertThat(masked, Matchers.endsWith(" done"));
	}

	@Test
	public void testMasksTheCredentialsOfAGoogleChatWebhook() {
		String url = "https://chat.googleapis.com/v1/spaces/AAAA/messages?key=" + "AIzaSy"
				+ "Dxyz1234567890abcdefghijklmn&token=" + "abcdefghij1234567890";

		String masked = SecretMasker.mask("posting to " + url);

		MatcherAssert.assertThat(masked, Matchers.containsString("spaces/AAAA/messages?"));
		MatcherAssert.assertThat(masked, Matchers.not(Matchers.containsString("AIzaSy")));
		MatcherAssert.assertThat(masked, Matchers.not(Matchers.containsString("abcdefghij1234")));
	}

	@Test
	public void testLeavesOrdinaryTextAlone() {
		String text = "Scan 42 of payments-7 finished in 1200 ms (github-pat rule, AKIA prefix)";

		Assertions.assertEquals(text, SecretMasker.mask(text));
		Assertions.assertNull(SecretMasker.mask(null));
	}
}
