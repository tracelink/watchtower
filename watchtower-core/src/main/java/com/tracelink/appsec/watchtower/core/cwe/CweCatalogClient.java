package com.tracelink.appsec.watchtower.core.cwe;

import java.io.IOException;
import java.util.List;
import java.util.Set;

/**
 * Reads the CWE catalog from its publisher. Kept as an interface so the refresh logic is tested without a network.
 * Every method either returns what was asked for or throws {@link IOException} with a message that is safe to show.
 */
public interface CweCatalogClient {

	/**
	 * @param version    the release, for example 4.20
	 * @param date       the release date, as the publisher gives it
	 * @param weaknesses how many weaknesses the release holds
	 */
	record Version(String version, String date, int weaknesses) {
	}

	Version version() throws IOException;

	/** @return the top-level entries (pillars) of the Research Concepts view */
	List<Integer> topLevelIds() throws IOException;

	/** @return every entry below {@code id} in the Research Concepts view, not including {@code id} */
	Set<Integer> descendantIds(int id) throws IOException;

	/** @return the entries for these numbers; numbers the publisher does not know are left out */
	List<CweEntry> weaknesses(List<Integer> ids) throws IOException;
}
