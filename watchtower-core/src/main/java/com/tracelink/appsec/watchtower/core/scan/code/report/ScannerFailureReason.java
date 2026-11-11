package com.tracelink.appsec.watchtower.core.scan.code.report;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Says, in a line a person can read, why a scanner is listed as failed: how many problems it
 * reported and the first few (a file and the kind of error). It never repeats the text a scanner
 * quotes from a file: a message is cut at its first quotation mark and at a fixed length, working
 * directories are removed from paths, and a secrets scanner gets only a count.
 *
 * @author Watchtower
 */
public final class ScannerFailureReason {

	/** How many distinct problems are named; the rest are counted. */
	static final int MAX_NAMED = 3;
	/** The longest piece of one message that is kept. */
	static final int MAX_PIECE = 90;

	// "In File '/tmp/reposcan-123/src/A.java' Error: LexException: ..." (PMD)
	private static final Pattern IN_FILE = Pattern.compile("In File '([^']+)' Error: (\\w+)");
	// Temporary scan directories at the front of a path
	private static final Pattern WORKDIR = Pattern.compile("/(?:private/)?(?:var/folders/[^/]+/[^/]+/T|tmp)/[^/\\s]+/");

	private ScannerFailureReason() {
	}

	/**
	 * @param messages  the scanner's error messages
	 * @param sensitive true for a scanner whose messages could carry secrets: only a count is said
	 * @return the sentence, or null when there is nothing to say
	 */
	public static String summarize(List<String> messages, boolean sensitive) {
		if (messages == null || messages.isEmpty()) {
			return null;
		}
		int total = messages.size();
		String count = total + (total == 1 ? " problem" : " problems");
		if (sensitive) {
			return count + " (details are not shown for a secrets scanner)";
		}
		Set<String> named = new LinkedHashSet<>();
		for (String message : messages) {
			String piece = piece(message);
			if (!piece.isBlank()) {
				named.add(piece);
			}
		}
		if (named.isEmpty()) {
			return count;
		}
		List<String> shown = named.stream().limit(MAX_NAMED).toList();
		int more = named.size() - shown.size();
		return count + ": " + String.join("; ", shown) + (more > 0 ? "; and " + more + " more" : "");
	}

	static String piece(String message) {
		if (message == null) {
			return "";
		}
		String cleaned = WORKDIR.matcher(message).replaceAll("");
		Matcher inFile = IN_FILE.matcher(cleaned);
		if (inFile.find()) {
			return WORKDIR.matcher(inFile.group(1)).replaceAll("") + " (" + inFile.group(2) + ")";
		}
		int quote = firstQuote(cleaned);
		String kept = (quote >= 0 ? cleaned.substring(0, quote) : cleaned).replaceAll("\\s+", " ").trim();
		kept = kept.replaceAll("[:\\-\\s]+$", "");
		return kept.length() > MAX_PIECE ? kept.substring(0, MAX_PIECE - 1).stripTrailing() + "…" : kept;
	}

	private static int firstQuote(String text) {
		int best = -1;
		for (char quote : new char[] {'\'', '"', '`'}) {
			int at = text.indexOf(quote);
			if (at >= 0 && (best < 0 || at < best)) {
				best = at;
			}
		}
		return best;
	}
}
