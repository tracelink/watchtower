package com.tracelink.appsec.watchtower.core.exception;

/**
 * Thrown when the SCM reports that a Pull Request does not exist.
 * <p>
 * Distinct from a plain {@linkplain ScanRejectedException} because the condition is
 * permanent: the Pull Request will not reappear, so retrying achieves nothing. Callers
 * use this to stop re-polling a row forever, which is the difference between a fixed cost
 * and one that grows for the lifetime of the install.
 *
 * @author csmith
 */
public class PullRequestNotFoundException extends ScanRejectedException {

	private static final long serialVersionUID = 1L;

	public PullRequestNotFoundException(String message) {
		super(message);
	}
}
