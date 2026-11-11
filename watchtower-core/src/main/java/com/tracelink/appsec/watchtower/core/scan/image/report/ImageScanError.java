package com.tracelink.appsec.watchtower.core.scan.image.report;

/**
 * Holds error information about a scan
 *
 * @author csmith
 */
public class ImageScanError {
	private final String message;

	public ImageScanError(String message) {
		this.message = message;
	}

	public String getErrorMessage() {
		return this.message;
	}
}
