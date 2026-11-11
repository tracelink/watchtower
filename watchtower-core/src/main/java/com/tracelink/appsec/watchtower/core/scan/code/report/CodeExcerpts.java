package com.tracelink.appsec.watchtower.core.scan.code.report;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.stream.Collectors;

import com.tracelink.appsec.watchtower.core.scan.code.scm.api.FileFetch;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResultCodeBlock;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResultCodeLine;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResultFile;

/**
 * The code a report shows for one file: a window of context around every flagged line, with
 * overlapping or abutting windows merged, so a file flagged on lines 5, 7 and 9 renders as one
 * continuous run rather than three near-identical snippets. Shared by the pull request and
 * repository scan reports, so both show and mask code the same way. Nothing here is stored.
 * <p>
 * A line flagged only by a sensitive scanner gets no context window - a secret's neighbours are
 * often the rest of it, such as a PEM body - and every rendered sensitive line is masked, even
 * one that only appears as another finding's context.
 *
 * @author Watchtower
 */
public final class CodeExcerpts {

	/**
	 * Shown in place of a line flagged by a sensitive scanner. The report says where the finding
	 * is, never what it is.
	 */
	public static final String MASKED_LINE_TEXT = "[hidden: flagged by a secrets scanner]";

	/** How many lines of context to show above and below a flagged line. */
	static final int CONTEXT_LINES = 5;

	private CodeExcerpts() {
	}

	/**
	 * @param fileName       the file
	 * @param content        its source, or null if the SCM did not return it
	 * @param plainLines     the 1-based line numbers flagged by a non-sensitive rule
	 * @param sensitiveLines the 1-based line numbers flagged by a sensitive rule
	 * @param findingCount   how many findings the file has
	 * @return the file as a report renders it
	 */
	public static PRScanResultFile of(String fileName, String content, Set<Integer> plainLines,
			Set<Integer> sensitiveLines, int findingCount) {
		return of(fileName, FileFetch.found(content), plainLines, sensitiveLines, findingCount);
	}

	/** As above, from a fetch that says why when the file could not be read. */
	public static PRScanResultFile of(String fileName, FileFetch fetch, Set<Integer> plainLines,
			Set<Integer> sensitiveLines, int findingCount) {
		if (fetch.content() == null) {
			return PRScanResultFile.withoutSource(fileName, findingCount, fetch.reason());
		}
		return PRScanResultFile.withSource(fileName,
				blocks(fetch.content().split("\n", -1), plainLines, sensitiveLines), findingCount);
	}

	/**
	 * @param fileLines      the file's content, split on newlines
	 * @param plainLines     the 1-based line numbers flagged by a non-sensitive rule
	 * @param sensitiveLines the 1-based line numbers flagged by a sensitive rule
	 * @return the contiguous runs of source to render, in file order
	 */
	public static List<PRScanResultCodeBlock> blocks(String[] fileLines, Set<Integer> plainLines,
			Set<Integer> sensitiveLines) {
		SortedSet<Integer> violationLines = new TreeSet<>(plainLines);
		violationLines.addAll(sensitiveLines);
		// Sorted by window start, not by flagged line: a context-less sensitive line can sit
		// after a plain line whose window opens earlier.
		List<int[]> windows = violationLines.stream()
				// A line past the end means the file has moved on since the scan ran, so there
				// is nothing honest to show for it
				.filter(line -> line >= 1 && line <= fileLines.length)
				.map(line -> contextWindow(line, fileLines.length, plainLines.contains(line)))
				.sorted(Comparator.comparingInt(window -> window[0]))
				.collect(Collectors.toList());

		List<PRScanResultCodeBlock> blocks = new ArrayList<>();
		int blockStart = -1;
		int blockEnd = -1;
		for (int[] window : windows) {
			int start = window[0];
			int end = window[1];
			if (blockStart == -1) {
				blockStart = start;
				blockEnd = end;
			} else if (start <= blockEnd + 1) {
				blockEnd = Math.max(blockEnd, end);
			} else {
				blocks.add(block(fileLines, blockStart, blockEnd, violationLines, sensitiveLines));
				blockStart = start;
				blockEnd = end;
			}
		}
		if (blockStart != -1) {
			blocks.add(block(fileLines, blockStart, blockEnd, violationLines, sensitiveLines));
		}
		return blocks;
	}

	/**
	 * @param line        the flagged 1-based line
	 * @param fileLength  the number of lines in the file
	 * @param withContext whether to show surrounding lines
	 * @return the inclusive {@code [start, end]} line range to render for the flagged line
	 */
	private static int[] contextWindow(int line, int fileLength, boolean withContext) {
		if (!withContext) {
			return new int[] {line, line};
		}
		return new int[] {Math.max(1, line - CONTEXT_LINES),
				Math.min(fileLength, line + CONTEXT_LINES)};
	}

	private static PRScanResultCodeBlock block(String[] fileLines, int startLine, int endLine,
			Set<Integer> violationLines, Set<Integer> sensitiveLines) {
		List<PRScanResultCodeLine> lines = new ArrayList<>();
		for (int lineNum = startLine; lineNum <= endLine; lineNum++) {
			String text = sensitiveLines.contains(lineNum) ? MASKED_LINE_TEXT
					: fileLines[lineNum - 1];
			lines.add(new PRScanResultCodeLine(lineNum, text, violationLines.contains(lineNum)));
		}
		return new PRScanResultCodeBlock(lines);
	}
}
