package com.tracelink.appsec.watchtower.core.scan.code.scm.bb;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.BBWebhookSignature;

public class BBWebhookSignatureTest {

	private static final String SECRET = "s3cr3t";
	private static final byte[] BODY =
			"{\"pullrequest\":{\"id\":1}}".getBytes(StandardCharsets.UTF_8);

	@Test
	public void testHeaderNameMatchesBitbucketsContract() {
		Assertions.assertEquals("X-Hub-Signature", BBWebhookSignature.HEADER_NAME);
	}

	@Test
	public void testRenderedHeaderCarriesTheSha256Prefix() {
		Assertions.assertTrue(
				BBWebhookSignature.headerValueFor(SECRET, BODY).startsWith("sha256="));
	}

	@Test
	public void testValidSignatureIsAccepted() {
		Assertions.assertTrue(BBWebhookSignature.isValid(SECRET, BODY,
				BBWebhookSignature.headerValueFor(SECRET, BODY)));
	}

	@Test
	public void testPrefixIsOptionalAndHexCaseInsensitive() {
		String withPrefix = BBWebhookSignature.headerValueFor(SECRET, BODY);
		String bareHex = withPrefix.substring("sha256=".length());

		Assertions.assertTrue(BBWebhookSignature.isValid(SECRET, BODY, bareHex));
		Assertions.assertTrue(
				BBWebhookSignature.isValid(SECRET, BODY, bareHex.toUpperCase()));
		Assertions.assertTrue(
				BBWebhookSignature.isValid(SECRET, BODY, "  " + withPrefix + "  "));
	}

	@Test
	public void testTamperedBodyIsRejected() {
		Assertions.assertFalse(BBWebhookSignature.isValid(SECRET,
				"{\"pullrequest\":{\"id\":2}}".getBytes(StandardCharsets.UTF_8),
				BBWebhookSignature.headerValueFor(SECRET, BODY)));
	}

	@Test
	public void testWrongSecretIsRejected() {
		Assertions.assertFalse(BBWebhookSignature.isValid(SECRET, BODY,
				BBWebhookSignature.headerValueFor("other-secret", BODY)));
	}

	@Test
	public void testSecretIsTrimmed() {
		// A secret pasted into the settings form routinely acquires a trailing newline.
		// It must still verify a signature produced with the intended value.
		Assertions.assertTrue(BBWebhookSignature.isValid("  " + SECRET + "\n", BODY,
				BBWebhookSignature.headerValueFor(SECRET, BODY)));
	}

	@Test
	public void testMissingSecretOrSignatureIsRejected() {
		String valid = BBWebhookSignature.headerValueFor(SECRET, BODY);
		Assertions.assertFalse(BBWebhookSignature.isValid(null, BODY, valid));
		Assertions.assertFalse(BBWebhookSignature.isValid("", BODY, valid));
		Assertions.assertFalse(BBWebhookSignature.isValid("   ", BODY, valid));
		Assertions.assertFalse(BBWebhookSignature.isValid(SECRET, BODY, null));
		Assertions.assertFalse(BBWebhookSignature.isValid(SECRET, BODY, ""));
		Assertions.assertFalse(BBWebhookSignature.isValid(SECRET, BODY, "sha256="));
		Assertions.assertFalse(BBWebhookSignature.isValid(SECRET, null, valid));
	}

	@Test
	public void testSignatureFollowsTheBytesNotTheDecodedText() {
		// The SCM signs the bytes it sent. A payload decoded with one charset and
		// re-encoded as another produces different bytes for the same characters, which
		// is what broke verification for a real payload containing U+200C.
		String text = "{\"author\":\"José\"}";
		byte[] utf8 = text.getBytes(StandardCharsets.UTF_8);
		byte[] latin1 = text.getBytes(StandardCharsets.ISO_8859_1);
		String signedOverUtf8 = BBWebhookSignature.headerValueFor(SECRET, utf8);

		Assertions.assertTrue(BBWebhookSignature.isValid(SECRET, utf8, signedOverUtf8));
		Assertions.assertFalse(BBWebhookSignature.isValid(SECRET, latin1, signedOverUtf8));
	}

	@Test
	public void testKnownAnswerMatchesTheDocumentedScheme() {
		// Fixed HMAC-SHA256 vector, so a change of algorithm, encoding or prefix is
		// caught rather than silently accepted.
		Assertions.assertEquals(
				"sha256=f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
				BBWebhookSignature.headerValueFor("key",
						"The quick brown fox jumps over the lazy dog"
								.getBytes(StandardCharsets.UTF_8)));
	}

	@Test
	public void testMatchesBitbucketsOwnDocumentedJavaExample() {
		// The exact secret, payload and expected signature published in the Java sample
		// on https://support.atlassian.com/bitbucket-cloud/docs/manage-webhooks/. Their
		// sample hashes a String literal's UTF-8 bytes directly - no JSON re-parsing, no
		// file I/O - which is a strictly simpler case than a real HTTP request and one
		// this class must reproduce exactly.
		String secret = "It's a Secret to Everybody";
		byte[] payload = "Hello World!".getBytes(StandardCharsets.UTF_8);
		String bitbucketsExpectedSignature =
				"sha256=a4771c39fbe90f317c7824e83ddef3caae9cb3d976c214ace1f2937e133263c9";

		Assertions.assertEquals(bitbucketsExpectedSignature,
				BBWebhookSignature.headerValueFor(secret, payload));
		Assertions.assertTrue(BBWebhookSignature.isValid(secret, payload,
				bitbucketsExpectedSignature));
	}
}
