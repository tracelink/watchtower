package com.tracelink.appsec.module.betterleaks.allowlist;

import java.util.List;

/**
 * Supplies the allowlist entries a scan applies.
 *
 * @author Watchtower
 */
@FunctionalInterface
public interface BetterleaksAllowlistProvider {

	/** No allowlist, for a scanner built outside a Spring context. */
	BetterleaksAllowlistProvider NONE = repositoryName -> List.of();

	/**
	 * @param repositoryName the scanned repository, or null if the scan has none
	 * @return the unexpired global entries plus that repository's entries
	 */
	List<BetterleaksAllowlistEntry> activeEntries(String repositoryName);
}
