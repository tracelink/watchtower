package com.tracelink.appsec.watchtower.core.scan.code;

/**
 * Compares commit ids that may be written in full or abbreviated. A pull request from Bitbucket carries 12-character commit ids while
 * the review of that pull request records the full 40 characters, so strict equality calls the same commit a different one.
 */
public final class CommitIds {

	/** Shortest commit prefix that still names one commit; shorter values are never taken as a match. */
	private static final int MIN_COMMIT_PREFIX = 7;

	private CommitIds() {
	}

	/**
	 * Whether two commit ids name the same commit: equal, or one a prefix of the other (ignoring case) that is long enough to be
	 * unambiguous. Null never matches, not even another null.
	 */
	public static boolean same(String a, String b) {
		if (a == null || b == null) {
			return false;
		}
		if (a.equals(b)) {
			return true;
		}
		String shorter = a.length() <= b.length() ? a : b;
		String longer = shorter == a ? b : a;
		return shorter.length() >= MIN_COMMIT_PREFIX && longer.regionMatches(true, 0, shorter, 0, shorter.length());
	}
}
