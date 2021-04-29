package com.tracelink.appsec.watchtower.core.report;

/**
 * Holds error information about a scan
 *
 * @author csmith
 */
public class ScanError {
	private final String message;

	public ScanError(String message) {
		this.message = message;
	}

	public String getErrorMessage() {
		return this.message;
	}
}
