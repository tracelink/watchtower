package com.tracelink.appsec.watchtower.core.scan.code;

import com.tracelink.appsec.watchtower.core.scan.ScanType;

/**
 * Enumeration of the supported types of scans
 * 
 * @author csmith
 *
 */
public enum CodeScanType implements ScanType {
	PULL_REQUEST("pull_request", "Pull Request"), UPLOAD("upload", "Upload");

	private final String typeName;
	private final String displayName;

	CodeScanType(String typeName, String displayName) {
		this.typeName = typeName;
		this.displayName = displayName;
	}

	@Override
	public String getTypeName() {
		return this.typeName;
	}

	@Override
	public String getDisplayName() {
		return this.displayName;
	}

}
