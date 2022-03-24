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
	private boolean benchmarkEnabled = false;
	/**
	 * whether debug is enabled for this scan
	 */
	private boolean debugEnabled = false;

	public void setRuleset(RulesetDto ruleset) {
		if (ruleset == null) {
			throw new IllegalArgumentException("Ruleset cannot be null.");
		}
		this.ruleset = ruleset;
	}

	public RulesetDto getRuleset() {
		return ruleset;
	}

	public boolean isBenchmarkEnabled() {
		return benchmarkEnabled;
	}

	public void setBenchmarkEnabled(boolean benchmarkEnabled) {
		this.benchmarkEnabled = benchmarkEnabled;
	}

	public boolean isDebugEnabled() {
		return debugEnabled;
	}

	public void setDebugEnabled(boolean debugEnabled) {
		this.debugEnabled = debugEnabled;
	}

}
