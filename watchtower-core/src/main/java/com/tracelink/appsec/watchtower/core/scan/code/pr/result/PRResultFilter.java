package com.tracelink.appsec.watchtower.core.scan.code.pr.result;

/**
 * An Enum of options to filter scan results for Pull Request Scans
 * 
 * @author csmith
 *
 */
public enum PRResultFilter {

	ALL("all", "All Scans"),
	//
	UNRESOLVED("unresolved", "Unresolved Pull Requests"),
	//
	VIOLATIONS("violations", "Scans with Violations");

	private final String name;

	private final String display;

	PRResultFilter(String name, String display) {
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
	 * @return the matching {@linkplain PRResultFilter} or null, if not found
	 */
	public static PRResultFilter toFilter(String name) {
		for (PRResultFilter rf : PRResultFilter.values()) {
			if (rf.name.equals(name)) {
				return rf;
			}
		}
		return null;
	}
}
