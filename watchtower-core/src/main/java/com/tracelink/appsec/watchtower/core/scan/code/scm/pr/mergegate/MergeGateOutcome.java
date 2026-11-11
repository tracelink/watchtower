package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.mergegate;

/**
 * What Watchtower knew about a pull request when it was merged: whether a completed scan of the
 * merged commit existed, and if it did, whether that scan blocked.
 *
 * @author Watchtower
 */
public enum MergeGateOutcome {
	/** A completed scan of the merged commit found nothing blocking. */
	SCANNED_CLEAN("Scanned, nothing blocking", Kind.GATED),
	/** The merged commit's scan blocked, and an approved bypass covered it. */
	BLOCKED_BYPASSED("Blocking findings, bypassed", Kind.BLOCKED),
	/** The merged commit's scan blocked, and nothing bypassed it. */
	BLOCKED_UNBYPASSED("Blocking findings, not bypassed", Kind.BLOCKED),
	/** A scan was queued or running when the pull request was merged. */
	SCAN_IN_PROGRESS("Scan in progress", Kind.BEFORE_SCAN),
	/** An earlier commit was scanned; the merged one was not. */
	NEWER_COMMIT_NOT_SCANNED("Newer commit not scanned", Kind.BEFORE_SCAN),
	/** The merged commit's scan failed. */
	SCAN_FAILED("Scan failed", Kind.BEFORE_SCAN),
	/** Watchtower never scanned the pull request. */
	NEVER_SCANNED("Never scanned", Kind.BEFORE_SCAN);

	/** The three groups the merge gate view counts. */
	public enum Kind {
		GATED, BLOCKED, BEFORE_SCAN
	}

	private final String label;
	private final Kind kind;

	MergeGateOutcome(String label, Kind kind) {
		this.label = label;
		this.kind = kind;
	}

	public String getLabel() {
		return label;
	}

	public Kind getKind() {
		return kind;
	}

	/** @return whether a merge gate would have held this merge */
	public boolean isUngated() {
		return this == BLOCKED_UNBYPASSED || kind == Kind.BEFORE_SCAN;
	}
}
