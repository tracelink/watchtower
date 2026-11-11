package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result;

import java.util.ArrayList;
import java.util.List;

/**
 * One tab of the pull request results page: a scan filter, or the merge gate view. The filters
 * stay an enum because the REST API takes them; the merge gate view is not a scan filter.
 *
 * @param name    the path segment, {@code /scan/results/{name}}
 * @param display the tab's label
 * @author Watchtower
 */
public record PRResultTab(String name, String display) {
	/** The merge gate view's path segment. */
	public static final String MERGE_GATE = "merge-gate";

	/** @return the results page's tabs, in order */
	public static List<PRResultTab> all() {
		List<PRResultTab> tabs = new ArrayList<>();
		for (PRResultFilter filter : PRResultFilter.values()) {
			tabs.add(new PRResultTab(filter.getName(), filter.getDisplay()));
		}
		tabs.add(new PRResultTab(MERGE_GATE, "Merge gate"));
		return List.copyOf(tabs);
	}

	/** For the shared filter tabs fragment, which reads {@code getName()}. */
	public String getName() {
		return name;
	}

	/** For the shared filter tabs fragment, which reads {@code getDisplay()}. */
	public String getDisplay() {
		return display;
	}
}
