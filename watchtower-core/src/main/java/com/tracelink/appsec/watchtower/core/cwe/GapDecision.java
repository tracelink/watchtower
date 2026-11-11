package com.tracelink.appsec.watchtower.core.cwe;

/** What a person decided about a weakness that no rule covers in one language. */
public enum GapDecision {
	/** The weakness does not apply to this language or environment. */
	NOT_APPLICABLE,
	/** The current engines cannot find it (for example it needs tracking across files). */
	NOT_COVERABLE,
	/** To be dealt with later. */
	DEFERRED
}
