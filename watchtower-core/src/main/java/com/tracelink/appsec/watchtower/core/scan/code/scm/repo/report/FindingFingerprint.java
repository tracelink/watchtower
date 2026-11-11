package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import org.apache.commons.lang3.StringUtils;

/**
 * Identifies one finding across scans of a branch. Hashes the rule, the file and the text of the
 * flagged line with whitespace collapsed, so a finding keeps its identity when lines above it
 * move. One-way: the line text cannot be recovered from a fingerprint, so storing it stores no
 * code.
 *
 * @author Watchtower
 */
public final class FindingFingerprint {

	private static final int HEX_LENGTH_BYTES = 16;

	private FindingFingerprint() {
	}

	/**
	 * @param rule     the rule's name
	 * @param file     the path relative to the repository root
	 * @param lineText the flagged line, or null if it could not be read
	 * @param message  the finding's message, used in place of an unreadable line
	 * @return 32 hex characters
	 */
	public static String of(String rule, String file, String lineText, String message) {
		String anchor = lineText != null ? StringUtils.normalizeSpace(lineText)
				: "message:" + StringUtils.defaultString(message);
		String canonical = StringUtils.defaultString(rule) + '\u0000'
				+ StringUtils.defaultString(file) + '\u0000' + anchor;
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256")
					.digest(canonical.getBytes(StandardCharsets.UTF_8));
			return HexFormat.of().formatHex(digest, 0, HEX_LENGTH_BYTES);
		} catch (NoSuchAlgorithmException e) {
			// Every JRE provides SHA-256
			throw new IllegalStateException(e);
		}
	}
}
