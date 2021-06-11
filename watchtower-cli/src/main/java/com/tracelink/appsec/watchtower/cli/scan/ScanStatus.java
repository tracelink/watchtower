package com.tracelink.appsec.watchtower.cli.scan;

/**
 * The status of a scan
 *
 * @author csmith
 */
public enum ScanStatus {
	NOT_STARTED("Not Started"), IN_PROGRESS("In Progress"), DONE("Done"), FAILED("Failed");

	private final String displayName;

	ScanStatus(String name) {
		this.displayName = name;
	}

	public String getDisplayName() {
		return this.displayName;
	}

	/**
	 * Convert a String representation of a scan status to a {@linkplain ScanStatus}
	 *
	 * @param name the display name of a {@linkplain ScanStatus}
	 * @return the enum value that matches the input, or null if not found
	 */
	public static ScanStatus toStatus(String name) {
		for (ScanStatus status : ScanStatus.values()) {
			if (status.getDisplayName().equals(name)) {
				return status;
			}
		}
		return null;
	}
}
