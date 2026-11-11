package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity;

/**
 * What a finished repository scan did. A scan can end without scanning: the branch head and
 * ruleset are unchanged since the last scan, or the repository is too large or too stale.
 *
 * @author Watchtower
 */
public enum RepoScanOutcome {
	SCANNED("Scanned"), UNCHANGED("Unchanged"), SKIPPED_SIZE("Too large"),
	SKIPPED_STALE("Stale"), BRANCH_MISSING("Branch missing");

	private final String displayName;

	RepoScanOutcome(String displayName) {
		this.displayName = displayName;
	}

	public String getDisplayName() {
		return displayName;
	}
}
