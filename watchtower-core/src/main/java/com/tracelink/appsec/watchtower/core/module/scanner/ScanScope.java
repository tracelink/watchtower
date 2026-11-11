package com.tracelink.appsec.watchtower.core.module.scanner;

/**
 * Declares how much of a repository's source a {@linkplain ICodeScanner} needs in order to run.
 * Lets {@code PRScanAgent} fetch only what is required for a given pull request scan instead of
 * always downloading the full repository zip.
 *
 * @author csmith, mcool
 */
public enum ScanScope {
	/** Only files changed in the pull request diff. */
	CHANGED_FILES,

	/** Specific file patterns regardless of what changed (e.g. {@code pom.xml} for SCA). */
	MANIFEST_FILES,

	/** Complete repository source — needed for cross-file data flow analysis. */
	FULL_SOURCE
}
