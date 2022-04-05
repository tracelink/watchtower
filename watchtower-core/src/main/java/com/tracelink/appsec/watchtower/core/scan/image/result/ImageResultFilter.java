package com.tracelink.appsec.watchtower.core.scan.image.result;

import com.tracelink.appsec.watchtower.core.scan.code.upload.result.UploadResultFilter;

public enum ImageResultFilter {
	ALL("all", "All Scans"),
	;
	private final String name;

	private final String display;

	ImageResultFilter(String name, String display) {
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
	public static ImageResultFilter toFilter(String name) {
		for (ImageResultFilter rf : ImageResultFilter.values()) {
			if (rf.name.equals(name)) {
				return rf;
			}
		}
		return null;
	}
}
