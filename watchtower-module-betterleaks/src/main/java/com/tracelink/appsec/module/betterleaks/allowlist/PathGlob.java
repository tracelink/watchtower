package com.tracelink.appsec.module.betterleaks.allowlist;

import java.util.Arrays;
import java.util.regex.Pattern;

/**
 * A validated repository-relative path glob for the Betterleaks allowlist, e.g.
 * {@code src/test/fixtures/**} or {@code *.lock}. The character set is deliberately small: it
 * keeps the generated regex free of anything a TOML literal string or RE2 could misread, so an
 * entry can never inject config.
 * <p>
 * {@code **} matches across directories, {@code *} and {@code ?} within one. A glob without a
 * {@code /} matches that file name at any depth, as in {@code .gitignore}.
 *
 * @param glob the glob, trimmed
 * @author Watchtower
 */
public record PathGlob(String glob) {

	static final int MAX_LENGTH = 300;

	private static final Pattern SAFE = Pattern.compile("[A-Za-z0-9._\\-/*?]+");

	/** Only wildcards and separators: would match (nearly) every file. */
	private static final Pattern MATCHES_EVERYTHING = Pattern.compile("[*/?]+");

	/** Matches any leading directories, including none. */
	private static final String ANY_DIRECTORIES = "(?:.*/)?";

	public PathGlob {
		if (glob == null || glob.isEmpty()) {
			throw new IllegalArgumentException("A path pattern is required.");
		}
		if (glob.length() > MAX_LENGTH) {
			throw new IllegalArgumentException(
					"Path patterns are limited to " + MAX_LENGTH + " characters.");
		}
		if (!SAFE.matcher(glob).matches()) {
			throw new IllegalArgumentException("Path patterns may only use letters, digits and"
					+ " the characters . _ - / * ?");
		}
		if (glob.startsWith("/")) {
			throw new IllegalArgumentException(
					"Path patterns are relative to the repository root; remove the leading /.");
		}
		if (Arrays.asList(glob.split("/")).contains("..")) {
			throw new IllegalArgumentException("Path patterns may not contain '..'.");
		}
		if (MATCHES_EVERYTHING.matcher(glob).matches()) {
			throw new IllegalArgumentException(
					"That pattern would allowlist every file; name a directory or file.");
		}
	}

	/**
	 * @param raw the glob as entered
	 * @return the validated glob
	 * @throws IllegalArgumentException if it is missing, too long, uses unsupported characters,
	 *                                  escapes the repository or matches everything
	 */
	public static PathGlob of(String raw) {
		return new PathGlob(raw == null ? null : raw.trim());
	}

	/**
	 * @return an anchored regex matching repository-relative paths the glob matches
	 */
	public String toRegex() {
		StringBuilder regex = new StringBuilder("^");
		if (!glob.contains("/")) {
			regex.append(ANY_DIRECTORIES);
		}
		int length = glob.length();
		for (int i = 0; i < length; i++) {
			char c = glob.charAt(i);
			if (c == '*' && i + 1 < length && glob.charAt(i + 1) == '*') {
				boolean directoryPrefix = i + 2 < length && glob.charAt(i + 2) == '/';
				regex.append(directoryPrefix ? ANY_DIRECTORIES : ".*");
				i += directoryPrefix ? 2 : 1;
			} else if (c == '*') {
				regex.append("[^/]*");
			} else if (c == '?') {
				regex.append("[^/]");
			} else if (c == '.') {
				regex.append("\\.");
			} else {
				// Letters, digits, '_', '-' and '/' are literal in both Java and RE2.
				regex.append(c);
			}
		}
		return regex.append('$').toString();
	}
}
