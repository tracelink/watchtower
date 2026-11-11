package com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang3.StringUtils;

/**
 * Verification of the HMAC signature Bitbucket Cloud sends with each webhook.
 * <p>
 * Deliberately Bitbucket-specific rather than shared: the header name, the value format
 * and the digest are all this SCM's own contract, and other providers differ. GitHub
 * sends {@code X-Hub-Signature-256}, GitLab sends a plain shared token in
 * {@code X-Gitlab-Token}. A single "generic" helper would only be generic by accident.
 * <p>
 * Per Atlassian's documented scheme
 * (https://support.atlassian.com/bitbucket-cloud/docs/manage-webhooks/):
 * <ul>
 * <li>header {@value #HEADER_NAME}</li>
 * <li>value {@code sha256=<hex digest>}</li>
 * <li>HMAC-SHA256, secret taken as UTF-8 bytes</li>
 * <li>computed over the body Bitbucket sent, compared in constant time</li>
 * </ul>
 * Hex encoding uses {@link HexFormat}, matching Bitbucket's own published Java example
 * exactly; that example is pinned as a test in {@code BBWebhookSignatureTest}.
 *
 * @author csmith
 */
public final class BBWebhookSignature {

	/**
	 * Header Bitbucket Cloud puts the signature in.
	 */
	public static final String HEADER_NAME = "X-Hub-Signature";

	private static final String HMAC_SHA256 = "HmacSHA256";

	private static final String SHA256_PREFIX = "sha256=";

	private static final HexFormat HEX = HexFormat.of();

	private BBWebhookSignature() {
		// utility class
	}

	/**
	 * Checks a webhook payload against the signature header Bitbucket sent with it.
	 * <p>
	 * The body must be the bytes as received. Atlassian's own Python sample re-serialises
	 * a payload with {@code json.dumps(..., separators=(',', ':'))} before signing, but
	 * that is only correct when the source is not already the raw wire bytes - it
	 * reconstructs compact JSON from a pretty-printed export. A server holds the real
	 * bytes already and must not re-serialise them: doing so can silently change the
	 * digest, for example if the original payload used {@code \\uXXXX} escapes for a
	 * non-ASCII character rather than raw UTF-8. This is what Atlassian's guidance means
	 * by "verify the HMAC signature by using the raw webhook".
	 *
	 * @param secret          the shared secret configured for this integration
	 * @param rawBody         the request body bytes exactly as received
	 * @param signatureHeader the {@value #HEADER_NAME} value, with or without the
	 *                        {@code sha256=} prefix
	 * @return true if the signature matches the payload
	 */
	public static boolean isValid(String secret, byte[] rawBody, String signatureHeader) {
		// Trimmed: a secret pasted into a settings form routinely picks up a trailing
		// newline, which changes the key and makes every signature mismatch with
		// nothing to show why.
		String key = StringUtils.trimToNull(secret);
		if (key == null || StringUtils.isBlank(signatureHeader) || rawBody == null) {
			return false;
		}
		String expected = headerValueFor(key, rawBody);
		String received = normalise(signatureHeader);

		// Constant time. equals() returns on the first differing character, and that
		// timing difference is enough to recover a valid signature one character at a
		// time.
		return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8),
				received.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * Renders a signature header value for a payload, in the form Bitbucket sends.
	 * <p>
	 * Useful for tests. Verification must still go through
	 * {@link #isValid(String, byte[], String)} so the comparison stays constant time.
	 *
	 * @param secret  the shared secret
	 * @param rawBody the payload bytes to sign
	 * @return the header value, including the {@code sha256=} prefix
	 */
	public static String headerValueFor(String secret, byte[] rawBody) {
		return SHA256_PREFIX + hexDigest(StringUtils.trimToEmpty(secret), rawBody);
	}

	/**
	 * Brings a received header value to the canonical {@code sha256=<lowercase hex>}
	 * form, tolerating a missing prefix and upper-case hex.
	 *
	 * @param signatureHeader the received header value
	 * @return the normalised value
	 */
	private static String normalise(String signatureHeader) {
		String hex = StringUtils.removeStartIgnoreCase(signatureHeader.trim(), SHA256_PREFIX);
		return SHA256_PREFIX + hex.toLowerCase();
	}

	private static String hexDigest(String secret, byte[] rawBody) {
		try {
			Mac mac = Mac.getInstance(HMAC_SHA256);
			mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC_SHA256));
			byte[] digest = mac.doFinal(rawBody);
			return HEX.formatHex(digest);
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			// HmacSHA256 is required of every JVM and the key is non-empty by this
			// point, so neither is a recoverable runtime condition.
			throw new IllegalStateException("Could not compute webhook signature", e);
		}
	}
}
