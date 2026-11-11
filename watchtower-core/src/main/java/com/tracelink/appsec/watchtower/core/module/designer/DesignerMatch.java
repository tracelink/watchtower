package com.tracelink.appsec.watchtower.core.module.designer;

import java.util.List;

/**
 * One result of running a rule in a rule designer: the 1-based line it matched in the sample and
 * what it says there. The designers draw these as "Line 5" chips that jump to the highlighted line
 * (UAT walkthrough, 2026-10-16). A result without a line is a message the engine reported instead
 * of a match, such as a parse error, and is drawn as a plain warning chip.
 */
public record DesignerMatch(Integer line, String message) {

	public DesignerMatch {
		if (line != null && line < 1) {
			throw new IllegalArgumentException("Match lines start at 1");
		}
		message = message == null ? "" : message;
	}

	public static DesignerMatch atLine(int line, String message) {
		return new DesignerMatch(line, message);
	}

	public static DesignerMatch note(String message) {
		return new DesignerMatch(null, message);
	}

	public boolean hasLine() {
		return line != null;
	}

	/** How many of the results are real matches (with a line), for the "2 matches" chip. */
	public static long countMatches(List<DesignerMatch> results) {
		return results == null ? 0 : results.stream().filter(DesignerMatch::hasLine).count();
	}
}
