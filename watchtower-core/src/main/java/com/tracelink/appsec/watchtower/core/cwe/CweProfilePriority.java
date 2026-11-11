package com.tracelink.appsec.watchtower.core.cwe;

/** How much a weakness matters in this installation. Order is most to least important. */
public enum CweProfilePriority {
	CRITICAL, HIGH, NORMAL;

	/** Priority bands for MITRE's Top 25: ranks 1-10 critical, 11-20 high, the rest normal. */
	static CweProfilePriority ofTop25Rank(int rank) {
		return rank <= 10 ? CRITICAL : rank <= 20 ? HIGH : NORMAL;
	}
}
