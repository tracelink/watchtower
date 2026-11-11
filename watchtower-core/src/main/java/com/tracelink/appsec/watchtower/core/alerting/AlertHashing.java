package com.tracelink.appsec.watchtower.core.alerting;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Stable, fixed-length keys for dedupe records and chat threads.
 *
 * @author Watchtower
 */
public final class AlertHashing {

	private AlertHashing() {
	}

	/**
	 * @param value any text
	 * @return its SHA-256, as 64 lower-case hex characters
	 */
	public static String sha256(String value) {
		try {
			return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
					.digest(value.getBytes(StandardCharsets.UTF_8)));
		} catch (NoSuchAlgorithmException e) {
			// Every JRE is required to provide SHA-256.
			throw new IllegalStateException("SHA-256 unavailable", e);
		}
	}
}
