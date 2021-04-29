package com.tracelink.appsec.watchtower.core.scan;

/**
 * Enumeration of the supported types of scans
 * 
 * @author csmith
 *
 */
public enum ScanType {
	PULL_REQUEST("pull_request", "Pull Request"), UPLOAD("upload", "Upload");

	private final String typeName;
	private final String displayName;

	ScanType(String typeName, String displayName) {
		this.typeName = typeName;
		this.displayName = displayName;
	}

	public String getTypeName() {
		return this.typeName;
	}

	public String getDisplayName() {
		return this.displayName;
	}

	/**
	 * Convert a string typeName to a {@linkplain ScanType}
	 * 
	 * @param typeName the string representation of a {@linkplain ScanType}
	 * @return The {@linkplain ScanType} for the input, or null if not found
	 */
	public static ScanType ofType(String typeName) {
		for (ScanType type : ScanType.values()) {
			if (type.getTypeName().equals(typeName)) {
				return type;
			}
		}
		return null;
	}
}
