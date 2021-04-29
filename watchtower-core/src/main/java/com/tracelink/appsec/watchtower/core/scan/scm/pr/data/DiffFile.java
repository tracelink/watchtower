package com.tracelink.appsec.watchtower.core.scan.scm.pr.data;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

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

	public DiffFile(String path, String diffid) {
		this.path = path;
		this.diffs = new ArrayList<DiffLine>();
		this.diffid = diffid;
	}

	/**
	 * Given an inputstream of the git diff, populate this object with the differences
	 *
	 * @param diffStream an Input stream of a git diff
	 * @throws IOException if an exception occurs while reading the stream
	 */
	public void parseDiff(InputStream diffStream) throws IOException {
		try (BufferedReader br = new BufferedReader(new InputStreamReader(diffStream))) {
			String line = null;
			int lineNum = 1;
			// first search for @@ to skip ahead
			while ((line = br.readLine()) != null) {
				if (line.startsWith("@@")) {
					break;
				}
			}
			while ((line = br.readLine()) != null) {
				char first = line.charAt(0);
				switch (first) {
					case '+':
						// this is a modified or added line
						addLine(new DiffLine(lineNum, DiffType.MODIFIED));
						lineNum++;
						break;
					case '-':
						// skip, don't increment the line count
						break;
					default:
						// this is an existing line, unmodified/not-added
						addLine(new DiffLine(lineNum, DiffType.EXISTING));
						lineNum++;
						break;
				}
			}
		}
	}

	public boolean hasDiffs() {
		return !this.diffs.isEmpty();
	}

	private void addLine(DiffLine diffLine) {
		this.diffs.add(diffLine);
	}

	public String getDiffId() {
		return this.diffid;
	}

	public String getPath() {
		return this.path;
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
