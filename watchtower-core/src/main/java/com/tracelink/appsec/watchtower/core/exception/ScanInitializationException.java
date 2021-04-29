package com.tracelink.appsec.watchtower.core.exception;

/**
 * Thrown when any part of the scanning infrastructure could not be initialized properly
 *
 * @author csmith
 */
public class ScanInitializationException extends Exception {
	private static final long serialVersionUID = -4169080726180640830L;

	public ScanInitializationException(String message) {
		super(message);
	}

	public ScanInitializationException(String message, Exception e) {
		super(message, e);
	}
}
