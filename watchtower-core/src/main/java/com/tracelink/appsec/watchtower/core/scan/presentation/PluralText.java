package com.tracelink.appsec.watchtower.core.scan.presentation;

/** A count with its noun, so "1 scan" never reads "1 scans". */
public final class PluralText {
	private PluralText() {
	}

	/** {@code count(1, "scan")} is "1 scan"; {@code count(2, "scan")} is "2 scans". */
	public static String count(long count, String noun) {
		return count + " " + noun + (count == 1 ? "" : "s");
	}

	/** For nouns whose plural is not the noun plus "s": {@code count(2, "repository", "repositories")}. */
	public static String count(long count, String one, String many) {
		return count + " " + (count == 1 ? one : many);
	}
}
