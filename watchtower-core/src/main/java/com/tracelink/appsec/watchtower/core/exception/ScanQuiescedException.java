package com.tracelink.appsec.watchtower.core.exception;

/**
 * Thrown when a scan is refused because the system is quiesced.
 * <p>
 * Distinct from a plain {@linkplain ScanRejectedException} because the condition is
 * temporary and operator-controlled: the caller should retry later rather than treat the
 * request as invalid. Callers map this to a retryable response.
 *
 * @author csmith
 */
public class ScanQuiescedException extends ScanRejectedException {

	private static final long serialVersionUID = 1L;

	public ScanQuiescedException(String message) {
		super(message);
	}
}
