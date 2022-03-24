package com.tracelink.appsec.watchtower.core.benchmark;

/**
 * All Timers for Benchmarking
 *
 * @author csmith
 */
public enum WatchtowerTimers implements TimerType {
	// scanner timers
	/**
	 * Do all pre-checks for the scanners
	 */
	SCAN_TEST_SETUP("Scan: Test Setup"),
	// Scanners timing
	/**
	 * Execute all scanners
	 */
	SCAN_ALL_SCANNERS("Scan: Execute scanners"),
	// report back
	/**
	 * Send the results
	 */
	SEND_REPORT("Results: Send Results");

	private final String name;

	WatchtowerTimers(String name) {
		this.name = name;
	}

	@Override
	public String getExternalName() {
		return name;
	}

}
