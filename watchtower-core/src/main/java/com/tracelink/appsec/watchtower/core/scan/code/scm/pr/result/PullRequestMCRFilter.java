package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result;

/**
 * An Enum of options to filter Pull Request Manual Code Reviews
 * 
 * @author droseen
 *
 */
public enum PullRequestMCRFilter {

	ALL("all", "All MCRs"),
	//
	PENDING("pending", "Pending Review"),
	//
	PROGRESS("progress", "In Progress"),
	//
	REVIEWED("reviewed", "Reviewed"),
	//
	RECOMMENDATIONS("recommendations", "Reviewed with Recommendations");

	private final String name;

	private final String display;

	PullRequestMCRFilter(String name, String display) {
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
	 * @return the matching {@linkplain PullRequestMCRFilter} or null, if not found
	 */
	public static PullRequestMCRFilter toFilter(String name) {
		for (PullRequestMCRFilter rf : PullRequestMCRFilter.values()) {
			if (rf.name.equals(name)) {
				return rf;
			}
		}
		return null;
	}
}
