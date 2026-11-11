package com.tracelink.appsec.watchtower.core.process;

/**
 * Thrown when an external process cannot be started or waiting for it is interrupted. A process
 * that starts and exits non-zero or times out is reported through {@link ProcessResult} instead.
 */
public class ProcessExecutionException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public ProcessExecutionException(String message, Throwable cause) {
		super(message, cause);
	}
}
