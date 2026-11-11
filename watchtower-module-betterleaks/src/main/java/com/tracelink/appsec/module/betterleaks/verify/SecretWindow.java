package com.tracelink.appsec.module.betterleaks.verify;

import java.util.List;

/**
 * The few lines around a flagged line, which are all that is handed to a live check: the rest of
 * the file never leaves Watchtower, and other secrets further away in it are not checked.
 *
 * @param text        the window's lines, each ending in {@code \n}
 * @param flaggedLine where the flagged line is in the window, 1-based
 * @author Watchtower
 */
record SecretWindow(String text, int flaggedLine) {

	/** Lines kept either side, enough for a secret whose rule matches over several lines. */
	static final int CONTEXT_LINES = 5;

	/**
	 * @param content the file as scanned
	 * @param line    the flagged line, 1-based
	 * @return the window, or null if the file has no such line
	 */
	static SecretWindow around(String content, int line) {
		List<String> lines = content.lines().toList();
		if (line < 1 || line > lines.size()) {
			return null;
		}
		int first = Math.max(1, line - CONTEXT_LINES);
		int last = Math.min(lines.size(), line + CONTEXT_LINES);
		StringBuilder window = new StringBuilder();
		lines.subList(first - 1, last).forEach(text -> window.append(text).append('\n'));
		return new SecretWindow(window.toString(), line - first + 1);
	}
}
