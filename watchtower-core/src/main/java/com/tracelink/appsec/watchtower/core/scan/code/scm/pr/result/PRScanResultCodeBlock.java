package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result;

import java.util.List;

/**
 * One contiguous run of source lines within a {@linkplain PRScanResultFile}'s snippet.
 * <p>
 * A file with violations on, say, lines 5 and 90 produces two blocks rather than one 90-line
 * snippet. The report page renders a gap marker between consecutive blocks, so the reader can see
 * that source was skipped instead of silently assuming the lines are adjacent.
 *
 * @author Watchtower
 */
public class PRScanResultCodeBlock {
	private final List<PRScanResultCodeLine> lines;

	public PRScanResultCodeBlock(List<PRScanResultCodeLine> lines) {
		this.lines = List.copyOf(lines);
	}

	public List<PRScanResultCodeLine> getLines() {
		return lines;
	}
}
