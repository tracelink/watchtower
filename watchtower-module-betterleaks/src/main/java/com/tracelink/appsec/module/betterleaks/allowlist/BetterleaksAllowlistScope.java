package com.tracelink.appsec.module.betterleaks.allowlist;

/**
 * Where a Betterleaks allowlist entry applies.
 *
 * @author Watchtower
 */
public enum BetterleaksAllowlistScope {
	/** Every scanned repository. */
	GLOBAL,
	/** One repository, by name. */
	REPO
}
