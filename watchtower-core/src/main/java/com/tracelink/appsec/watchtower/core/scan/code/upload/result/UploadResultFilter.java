package com.tracelink.appsec.watchtower.core.scan.code.upload.result;

/**
 * An Enum of options to filter scan results for Upload Scans
 * 
 * @author csmith
 *
 */
public enum UploadResultFilter {
	ALL("all", "All Scans"),
	//
	VIOLATIONS("violations", "Scans with Violations"),
	//
	INCOMPLETE("incomplete", "Incomplete Scans");

	private final String name;

	private final String display;

	UploadResultFilter(String name, String display) {
		this.name = name;
		this.display = display;
	}

	public String getName() {
		return this.name;
	}

	public String getDisplay() {
		return display;
	}

	/**
	 * Get the Filter for the given name
	 * 
	 * @param name the name of the filter
	 * @return the matching {@linkplain UploadResultFilter} or null, if not found
	 */
	public static UploadResultFilter toFilter(String name) {
		for (UploadResultFilter rf : UploadResultFilter.values()) {
			if (rf.name.equals(name)) {
				return rf;
			}
		}
		return null;
	}
}
