package com.tracelink.appsec.watchtower.core.scan;

import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

/**
 * Scan configuration object managing all sub-configurations
 *
 * @author csmith, mcool
 */
public abstract class AbstractScanConfig {
	/**
	 * ruleset DTO object for this scan
	 */
	private RulesetDto ruleset;

	/**
	 * whether benchmarking is enabled for this scan
	 */
	private boolean benchmarkingEnabled;

	public void setRuleset(RulesetDto ruleset) {
		if (ruleset == null) {
			throw new IllegalArgumentException("Ruleset cannot be null.");
		}
		this.ruleset = ruleset;
	}

	public RulesetDto getRuleset() {
		return ruleset;
	}

	public void setBenchmarkEnabled(boolean enabled) {
		this.benchmarkingEnabled = enabled;
	}

	public boolean isBenchmarkEnabled() {
		return benchmarkingEnabled;
	}
}
