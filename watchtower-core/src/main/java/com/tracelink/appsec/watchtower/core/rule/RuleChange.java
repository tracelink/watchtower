package com.tracelink.appsec.watchtower.core.rule;

/**
 * What happened to a rule after a scan used it. A report reads a finding's guidance from the rule
 * as it is now, so a report says when that is not what the rule said when the scan ran.
 */
public enum RuleChange {

	/** The rule was edited after the scan. */
	CHANGED("Rule changed",
			"The rule was edited after this scan. The text shown is the rule's current guidance, "
					+ "not what it said when the scan ran."),

	/** The rule no longer exists. */
	DELETED("Rule deleted",
			"This rule no longer exists, so there is no guidance to show. The finding itself is kept.");

	private final String label;

	private final String tip;

	RuleChange(String label, String tip) {
		this.label = label;
		this.tip = tip;
	}

	/** @return the chip text */
	public String label() {
		return label;
	}

	/** @return the hover text */
	public String tip() {
		return tip;
	}
}
