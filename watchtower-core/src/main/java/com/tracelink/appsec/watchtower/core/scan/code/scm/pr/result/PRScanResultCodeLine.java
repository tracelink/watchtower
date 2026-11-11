package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result;

/**
 * One line of source in a {@linkplain PRScanResultCodeBlock}, shown in the code section of the PR
 * scan report so a reviewer can see the flagged code without leaving Watchtower.
 * <p>
 * {@code violationLine} marks a line the scan actually flagged; the report highlights those lines
 * and anchors the findings table's file links at them.
 *
 * @author Watchtower
 */
public class PRScanResultCodeLine {
	private final int lineNumber;

	private final String text;

	private final boolean violationLine;

	public PRScanResultCodeLine(int lineNumber, String text, boolean violationLine) {
		this.lineNumber = lineNumber;
		this.text = text;
		this.violationLine = violationLine;
	}

	public int getLineNumber() {
		return lineNumber;
	}

	public String getText() {
		return text;
	}

	public boolean isViolationLine() {
		return violationLine;
	}
}
