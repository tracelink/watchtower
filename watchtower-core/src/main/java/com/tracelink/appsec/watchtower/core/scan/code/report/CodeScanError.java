package com.tracelink.appsec.watchtower.core.scan.code.report;

/**
 * Holds error information about a scan
 *
 * @author csmith
 */
public class CodeScanError {
	private final String message;

	public CodeScanError(String message) {
		this.message = message;
	}

	public String getErrorMessage() {
		return this.message;
	}
}
