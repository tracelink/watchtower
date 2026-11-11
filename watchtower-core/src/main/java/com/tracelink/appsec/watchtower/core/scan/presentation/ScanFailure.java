package com.tracelink.appsec.watchtower.core.scan.presentation;

import java.util.regex.Pattern;

/**
 * Why an upload scan failed, for people: a short headline, what to do, and the original message as
 * the technical detail. Server working folders (temporary upload paths) are removed from the detail
 * so a report never shows where the server unpacks archives.
 */
public record ScanFailure(String headline, String hint, String detail) {

	/** Everything up to and including the folder an archive is unpacked into. */
	private static final Pattern STAGING_PREFIX = Pattern.compile("(?:/[^\\s/]+)+/src_staging/");
	/** An absolute path under a temporary folder, up to its last folder. */
	private static final Pattern TEMP_FOLDERS = Pattern.compile("/(?:tmp|var/folders|private/var)(?:/[^\\s/]+)*/");
	private static final String UNMAPPABLE = "unmappable characters";

	public static ScanFailure of(String message) {
		if (message == null || message.isBlank()) {
			return null;
		}
		String detail = withoutServerPaths(message);
		if (message.contains(UNMAPPABLE)) {
			return new ScanFailure("Couldn't read the archive",
					"A file name inside the ZIP uses characters the server can't read. "
							+ "Re-create the ZIP with plain file names and upload it again.",
					detail);
		}
		return new ScanFailure("The scan failed",
				"Upload the archive again. If it fails again, ask an administrator to check the logs.", detail);
	}

	public static String withoutServerPaths(String message) {
		if (message == null) {
			return null;
		}
		String withoutStaging = STAGING_PREFIX.matcher(message).replaceAll("");
		return TEMP_FOLDERS.matcher(withoutStaging).replaceAll("");
	}
}
