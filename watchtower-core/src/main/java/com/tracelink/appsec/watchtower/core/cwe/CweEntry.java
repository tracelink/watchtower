package com.tracelink.appsec.watchtower.core.cwe;

import java.util.List;
import java.util.Set;

/**
 * One weakness from the MITRE CWE catalog, trimmed to what Watchtower uses.
 *
 * @param id          the CWE number
 * @param name        the weakness name
 * @param abstraction Pillar, Class, Base, Variant or Compound
 * @param structure   Simple, Composite or Chain
 * @param status      Stable, Draft, Incomplete, Deprecated...
 * @param usage       MITRE's mapping guidance: Allowed, Allowed-with-Review, Discouraged or Prohibited
 * @param description a short plain-text description
 * @param likelihood  likelihood of exploit, when MITRE gives one
 * @param parents     the CWE numbers this one is a child of in the Research Concepts view
 */
public record CweEntry(int id, String name, String abstraction, String structure, String status, String usage,
		String description, String likelihood, List<Integer> parents) {

	/** Mapping guidance that tells people not to use an entry for a new mapping. */
	private static final Set<String> NOT_FOR_MAPPING = Set.of("Discouraged", "Prohibited");

	public CweEntry {
		parents = parents == null ? List.of() : List.copyOf(parents);
	}

	/** @return the number as people write it, for example {@code CWE-79} */
	public String label() {
		return "CWE-" + id;
	}

	/** @return whether MITRE allows mapping a new weakness to this entry */
	public boolean isMappable() {
		return !NOT_FOR_MAPPING.contains(usage);
	}
}
