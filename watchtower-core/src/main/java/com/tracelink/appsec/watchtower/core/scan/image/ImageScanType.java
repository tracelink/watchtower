package com.tracelink.appsec.watchtower.core.scan.image;

import com.tracelink.appsec.watchtower.core.scan.ScanType;

/**
 * Enumeration of the supported types of scans
 * 
 * @author csmith
 *
 */
public enum ImageScanType implements ScanType {
	CONTAINER("container", "Container");

	private final String typeName;
	private final String displayName;

	ImageScanType(String typeName, String displayName) {
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
