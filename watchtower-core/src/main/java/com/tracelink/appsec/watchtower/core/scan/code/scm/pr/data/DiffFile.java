package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.data;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A Diff File parses a git diff and labels each line as being Modified or Existing. This is
 * typically an expensive operation and should be used sparingly
 *
 * @author csmith
 */
public class DiffFile {
	private List<DiffLine> diffs;
	private String path;
	private String diffid;
	/**
	 * Whether the parsed diff contained at least one hunk, i.e. whether this file was
	 * touched by the pull request at all. Tracked separately from {@link #diffs} because
	 * a hunk consisting only of deletions records no line numbers, yet the file is still
	 * part of the diff.
	 */
	private boolean sawHunkHeader;

	public DiffFile(String path, String diffid) {
		this.path = path;
		this.diffs = new ArrayList<DiffLine>();
		this.diffid = diffid;
	}

	/**
	 * Matches a unified diff hunk header, capturing the start line in the new file.
	 * <p>
	 * The format is {@code @@ -oldStart[,oldCount] +newStart[,newCount] @@}, where the
	 * {@code ,count} parts are optional (git omits them when the count is 1).
	 */
	private static final Pattern HUNK_HEADER =
			Pattern.compile("^@@ -\\d+(?:,\\d+)? \\+(\\d+)(?:,\\d+)? @@");

	/**
	 * Line number to assume when a hunk header cannot be read. Treating it as the first
	 * line of the file preserves the behaviour this parser had before it understood
	 * hunk headers.
	 */
	private static final int DEFAULT_HUNK_START = 1;

	/**
	 * Given an inputstream of the git diff, populate this object with the differences
	 * <p>
	 * Line numbers are those of the <em>new</em> version of the file: each hunk restarts
	 * numbering from the start line declared in its {@code @@} header, added lines
	 * consume a line number, and deleted lines do not.
	 * <p>
	 * A stream containing more than one file's diff (multiple {@code diff --git} stanzas) is
	 * tolerated but not split apart - every stanza's lines accumulate into this single
	 * {@code DiffFile}. Use {@link #parseMultiFileDiff(InputStream, String)} to parse each
	 * file's changes into its own {@code DiffFile}.
	 *
	 * @param diffStream an Input stream of a git diff
	 * @throws IOException if an exception occurs while reading the stream
	 */
	public void parseDiff(InputStream diffStream) throws IOException {
		consumeLines(readLines(diffStream));
	}

	/**
	 * Splits a unified diff covering multiple files into one {@link DiffFile} per file.
	 * <p>
	 * Sections are delimited by {@code diff --git a/<path> b/<path>} lines, which is how git
	 * (and Bitbucket's {@code /diff} endpoint) separates files in a combined diff. Each
	 * section is parsed with exactly the same hunk-based line classification as
	 * {@link #parseDiff(InputStream)}.
	 *
	 * @param diffStream an input stream of a unified diff covering one or more files
	 * @param diffId     the diff id to stamp onto every resulting {@link DiffFile}
	 * @return a map of the new-file path (the file's path as it exists after the pull request,
	 *         or its former path for a deleted file) to the {@link DiffFile} describing that
	 *         file's changes
	 * @throws IOException if an exception occurs while reading the stream
	 */
	public static Map<String, DiffFile> parseMultiFileDiff(InputStream diffStream, String diffId)
			throws IOException {
		Map<String, DiffFile> result = new LinkedHashMap<>();
		List<String> section = null;
		for (String line : readLines(diffStream)) {
			if (line.startsWith("diff --git ")) {
				addSection(result, section, diffId);
				section = new ArrayList<>();
			} else if (section == null) {
				// Content before the first "diff --git" line, if any, is not part of any
				// file's diff.
				continue;
			}
			section.add(line);
		}
		addSection(result, section, diffId);
		return result;
	}

	private static void addSection(Map<String, DiffFile> result, List<String> section,
			String diffId) {
		if (section == null) {
			return;
		}
		String path = resolveSectionPath(section);
		if (path == null) {
			// A section with no discoverable path is not usable for violation
			// classification (which keys on file path); skip it rather than guessing.
			return;
		}
		DiffFile diffFile = new DiffFile(path, diffId);
		diffFile.consumeLines(section);
		result.put(path, diffFile);
	}

	/**
	 * Matches the file path out of a unified diff's {@code --- a/<path>}, {@code +++ b/<path>}
	 * or {@code diff --git a/<path> b/<path>} lines.
	 */
	private static final Pattern NEW_FILE_LINE = Pattern.compile("^\\+\\+\\+ b/(.+)$");
	private static final Pattern OLD_FILE_LINE = Pattern.compile("^--- a/(.+)$");
	private static final Pattern DIFF_GIT_LINE =
			Pattern.compile("^diff --git a/(.+?) b/(.+)$");

	/**
	 * Determines the path a diff section describes.
	 * <p>
	 * Prefers the post-change path ({@code +++ b/<path>}), since that is what violations are
	 * reported against. Falls back to the pre-change path for a deleted file
	 * ({@code +++ /dev/null}), and finally to the {@code diff --git} header itself for a
	 * binary file, which has neither a {@code ---} nor a {@code +++} line.
	 *
	 * @param section the lines of one file's diff section, including its {@code diff --git}
	 *                header
	 * @return the resolved path, or null if none of the expected lines were present
	 */
	private static String resolveSectionPath(List<String> section) {
		String oldPath = null;
		for (String line : section) {
			// The regex itself excludes "+++ /dev/null" (a deleted file), since it
			// requires a "b/" prefix that "/dev/null" does not have.
			Matcher newFile = NEW_FILE_LINE.matcher(line);
			if (newFile.matches()) {
				return newFile.group(1);
			}
			Matcher oldFile = OLD_FILE_LINE.matcher(line);
			if (oldFile.matches()) {
				oldPath = oldFile.group(1);
			}
			Matcher diffGit = DIFF_GIT_LINE.matcher(line);
			if (diffGit.matches() && oldPath == null) {
				oldPath = diffGit.group(2);
			}
		}
		return oldPath;
	}

	private static List<String> readLines(InputStream diffStream) throws IOException {
		List<String> lines = new ArrayList<>();
		try (BufferedReader br = new BufferedReader(new InputStreamReader(diffStream))) {
			String line;
			while ((line = br.readLine()) != null) {
				lines.add(line);
			}
		}
		return lines;
	}

	/**
	 * Classifies each line of a (single file's) diff as modified or existing, appending the
	 * results to {@link #diffs}. Shared by {@link #parseDiff(InputStream)} and
	 * {@link #parseMultiFileDiff(InputStream, String)} so both parse identically.
	 *
	 * @param lines the lines of a git diff, or one file's section of a multi-file diff
	 */
	private void consumeLines(List<String> lines) {
		int lineNum = DEFAULT_HUNK_START;
		// Content is only meaningful inside a hunk. Everything before the first
		// "@@" is file header noise, and in a multi-file diff the headers between
		// hunks include "--- a/file" and "+++ b/file", which would otherwise be
		// mistaken for deleted and added source lines.
		boolean inHunk = false;
		for (String line : lines) {
			if (line.startsWith("Binary files ") && line.endsWith(" differ")) {
				// A binary file has no line-level diff to report, but it was touched by
				// the pull request - the same reasoning as a deletion-only hunk below.
				sawHunkHeader = true;
				inHunk = false;
				continue;
			}
			if (line.startsWith("@@")) {
				lineNum = parseHunkStart(line);
				inHunk = true;
				sawHunkHeader = true;
				continue;
			}
			if (line.startsWith("diff --git")) {
				inHunk = false;
				continue;
			}
			if (!inHunk) {
				continue;
			}
			if (line.isEmpty()) {
				// A well-formed diff renders an unchanged empty line as a single
				// space, but tolerate a bare empty line rather than throwing.
				addLine(new DiffLine(lineNum, DiffType.EXISTING));
				lineNum++;
				continue;
			}
			switch (line.charAt(0)) {
				case '+':
					// this is a modified or added line
					addLine(new DiffLine(lineNum, DiffType.MODIFIED));
					lineNum++;
					break;
				case '-':
					// deleted: absent from the new file, so it consumes no line
					break;
				case '\\':
					// "\ No newline at end of file" is a marker, not source
					break;
				default:
					// this is an existing line, unmodified/not-added
					addLine(new DiffLine(lineNum, DiffType.EXISTING));
					lineNum++;
					break;
			}
		}
	}

	/**
	 * Reads the new-file start line out of a hunk header.
	 *
	 * @param header a line beginning with {@code @@}
	 * @return the line number the hunk starts at in the new file, or
	 *         {@link #DEFAULT_HUNK_START} if the header cannot be parsed
	 */
	private int parseHunkStart(String header) {
		Matcher matcher = HUNK_HEADER.matcher(header);
		if (matcher.find()) {
			return Integer.parseInt(matcher.group(1));
		}
		return DEFAULT_HUNK_START;
	}

	/**
	 * Whether this file was changed by the pull request.
	 * <p>
	 * True as soon as the diff contained a hunk, even if that hunk recorded no line
	 * numbers. A deletion-only hunk is the case that matters: it has no added lines and,
	 * at {@code context=0}, no context lines either, but the file was still modified.
	 *
	 * @return true if the diff described any change to this file
	 */
	public boolean hasDiffs() {
		return this.sawHunkHeader || !this.diffs.isEmpty();
	}

	private void addLine(DiffLine diffLine) {
		this.diffs.add(diffLine);
	}

	/**
	 * Counts the lines this diff reports as modified or added.
	 * <p>
	 * Intended for diagnostics. A file where {@link #hasDiffs()} is true but this count
	 * is zero was changed only by deletions.
	 *
	 * @return the number of modified lines recorded for this file
	 */
	public long getModifiedLineCount() {
		return this.diffs.stream().filter(d -> d.getType().equals(DiffType.MODIFIED)).count();
	}

	public String getDiffId() {
		return this.diffid;
	}

	public String getPath() {
		return this.path;
	}
	/** Source-free changed-line index for durable provider relevance checks. */
	public List<Integer> changedLines() {
		return diffs.stream().filter(d -> d.getType() == DiffType.MODIFIED).map(DiffLine::getLineNum).distinct().sorted().toList();
	}

	/**
	 * Checks if a given line number was pre-existing. E.g. is not modified or deleted
	 *
	 * @param lineNum the line to check
	 * @return true if the line was not modified or deleted
	 */
	public boolean isLineExisting(int lineNum) {
		return diffs.stream().anyMatch(
				d -> (d.getLineNum() == lineNum && d.getType().equals(DiffType.EXISTING)));
	}

	/**
	 * Checks if a given line number was changed. E.g. was modified
	 *
	 * @param lineNum the line to check
	 * @return true if the line was modified
	 */
	public boolean isLineChanged(int lineNum) {
		return diffs.stream().anyMatch(
				d -> (d.getLineNum() == lineNum && d.getType().equals(DiffType.MODIFIED)));
	}

}
